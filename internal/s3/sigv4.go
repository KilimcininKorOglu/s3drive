package s3

import (
	"cmp"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"s3drive/internal/pctenc"
	"s3drive/internal/store"
)

// AuthError is a failed S3 request signature.
type AuthError struct {
	Code    string
	Message string
	Status  int
}

func (e *AuthError) Error() string { return e.Code + ": " + e.Message }

func authErr(code, format string, args ...any) *AuthError {
	status := http.StatusForbidden
	if code == "RequestTimeTooSkewed" {
		status = http.StatusForbidden
	}
	return &AuthError{Code: code, Message: fmt.Sprintf(format, args...), Status: status}
}

// Auth is the verified request signature.
type Auth struct {
	AccessKey   string
	Key         *store.AccessKey
	PayloadHash string
	Signature   string
	SigningKey  []byte
	Scope       string
	DateTime    string
	Presigned   bool
}

// Authenticator verifies AWS Signature V4 for header and query requests.
type Authenticator struct {
	Store *store.Store
	Now   func() time.Time
}

// Authenticate verifies r and returns the signing context.
func (a *Authenticator) Authenticate(r *http.Request) (*Auth, *AuthError) {
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	if alg := r.URL.Query().Get("X-Amz-Algorithm"); alg != "" {
		return a.verifyPresigned(r, now)
	}
	return a.verifyHeader(r, now)
}

func (a *Authenticator) verifyHeader(r *http.Request, now time.Time) (*Auth, *AuthError) {
	in, aerr := parseAuthorization(r.Header.Get("Authorization"))
	if aerr != nil {
		return nil, aerr
	}
	if in.datetime, aerr = headerDateTime(r, now, in.date); aerr != nil {
		return nil, aerr
	}
	in.payloadHash = cmp.Or(r.Header.Get("X-Amz-Content-Sha256"), "UNSIGNED-PAYLOAD")
	return a.checkSignature(r, now, in)
}

// sigInput is the signed material shared by header and presigned SigV4.
type sigInput struct {
	accessKey, date, region, datetime     string
	signedHeaders, signature, payloadHash string
}

// parseAuthorization reads an "AWS4-HMAC-SHA256 Credential=...,
// SignedHeaders=..., Signature=..." header.
func parseAuthorization(authz string) (sigInput, *AuthError) {
	var in sigInput
	if authz == "" {
		return in, authErr("AccessDenied", "anonymous request is not allowed")
	}
	rest, ok := strings.CutPrefix(authz, "AWS4-HMAC-SHA256 ")
	if !ok {
		return in, authErr("InvalidRequest", "unsupported authorization algorithm")
	}
	fields := map[string]string{}
	for part := range strings.SplitSeq(rest, ",") {
		if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok {
			fields[k] = v
		}
	}
	credential, signedHeaders, signature := fields["Credential"], fields["SignedHeaders"], fields["Signature"]
	if credential == "" || signedHeaders == "" || signature == "" {
		return in, authErr("InvalidRequest", "malformed Authorization header")
	}
	in.signedHeaders, in.signature = signedHeaders, signature
	if in.accessKey, _, in.date, in.region, ok = parseCredential(credential); !ok {
		return in, authErr("InvalidRequest", "malformed credential scope")
	}
	return in, nil
}

// headerDateTime returns X-Amz-Date (or Date) after checking the 15-minute
// skew window and that it matches the credential date.
func headerDateTime(r *http.Request, now time.Time, date string) (string, *AuthError) {
	datetime := cmp.Or(r.Header.Get("X-Amz-Date"), r.Header.Get("Date"))
	t, err := time.Parse("20060102T150405Z", datetime)
	if err != nil {
		return "", authErr("RequestTimeTooSkewed", "missing or invalid x-amz-date")
	}
	if d := now.Sub(t); d > 15*time.Minute || d < -15*time.Minute {
		return "", authErr("RequestTimeTooSkewed", "request time is too far from server time")
	}
	if date != datetime[:8] {
		return "", authErr("InvalidRequest", "credential date does not match x-amz-date")
	}
	return datetime, nil
}

// checkSignature loads an active, unexpired access key and compares the
// SigV4 signature in constant time.
func (a *Authenticator) checkSignature(r *http.Request, now time.Time, in sigInput) (*Auth, *AuthError) {
	keyRow, err := a.Store.GetAccessKey(r.Context(), in.accessKey)
	if err != nil || !keyRow.Active {
		return nil, authErr("InvalidAccessKeyId", "the access key does not exist or is disabled")
	}
	if !keyRow.ExpiresAt.IsZero() && !now.Before(keyRow.ExpiresAt) {
		return nil, authErr("AccessDenied", "this access key has expired")
	}
	canonical, aerr := canonicalRequest(r, in.signedHeaders, in.payloadHash)
	if aerr != nil {
		return nil, aerr
	}
	scopeLine := in.date + "/" + in.region + "/s3/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + in.datetime + "\n" + scopeLine + "\n" + sha256Hex(canonical)
	key := signingKey(keyRow.Secret, in.date, in.region, "s3")
	expected := hex.EncodeToString(hmacSHA256(key, stringToSign))
	signature := strings.ToLower(in.signature)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(signature)) != 1 {
		return nil, authErr("SignatureDoesNotMatch", "the request signature we calculated does not match the signature you provided")
	}
	a.Store.TouchAccessKey(r.Context(), in.accessKey)
	return &Auth{
		AccessKey: in.accessKey, Key: keyRow, PayloadHash: in.payloadHash, Signature: signature,
		SigningKey: key, Scope: scopeLine, DateTime: in.datetime,
	}, nil
}

func (a *Authenticator) verifyPresigned(r *http.Request, now time.Time) (*Auth, *AuthError) {
	q := r.URL.Query()
	if q.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" {
		return nil, authErr("InvalidRequest", "unsupported presign algorithm")
	}
	credential := q.Get("X-Amz-Credential")
	signedHeaders := q.Get("X-Amz-SignedHeaders")
	signature := q.Get("X-Amz-Signature")
	datetime := q.Get("X-Amz-Date")
	if credential == "" || signedHeaders == "" || signature == "" || datetime == "" {
		return nil, authErr("InvalidRequest", "incomplete presigned request")
	}
	in := sigInput{signedHeaders: signedHeaders, signature: signature, datetime: datetime}
	var ok bool
	if in.accessKey, _, in.date, in.region, ok = parseCredential(credential); !ok {
		return nil, authErr("InvalidRequest", "malformed credential scope")
	}
	if aerr := checkPresignWindow(q, in.date, datetime, now); aerr != nil {
		return nil, aerr
	}
	in.payloadHash = cmp.Or(q.Get("X-Amz-Content-Sha256"), "UNSIGNED-PAYLOAD")
	auth, aerr := a.checkSignature(r, now, in)
	if aerr != nil {
		return nil, aerr
	}
	auth.Presigned = true
	return auth, nil
}

// checkPresignWindow validates X-Amz-Date against the credential date and
// the X-Amz-Expires window (1 s to 7 days, at most 15 min in the future).
func checkPresignWindow(q url.Values, date, datetime string, now time.Time) *AuthError {
	t, err := time.Parse("20060102T150405Z", datetime)
	if err != nil {
		return authErr("RequestTimeTooSkewed", "invalid X-Amz-Date")
	}
	if date != datetime[:8] {
		return authErr("InvalidRequest", "credential date does not match X-Amz-Date")
	}
	expires, err := strconv.ParseInt(q.Get("X-Amz-Expires"), 10, 64)
	if err != nil || expires < 1 || expires > 604800 {
		return authErr("InvalidRequest", "X-Amz-Expires must be between 1 and 604800 seconds")
	}
	if now.After(t.Add(time.Duration(expires) * time.Second)) {
		return authErr("AccessDenied", "request has expired")
	}
	if t.After(now.Add(15 * time.Minute)) {
		return authErr("RequestTimeTooSkewed", "presigned request is from the future")
	}
	return nil
}

func parseCredential(cred string) (accessKey, scope, date, region string, ok bool) {
	parts := strings.Split(cred, "/")
	if len(parts) != 5 || parts[4] != "aws4_request" {
		return "", "", "", "", false
	}
	return parts[0], strings.Join(parts[1:], "/"), parts[1], parts[2], true
}

// canonicalRequest builds the AWS SigV4 canonical request.
func canonicalRequest(r *http.Request, signedHeaders, payloadHash string) (string, *AuthError) {
	uri := r.URL.EscapedPath()
	if uri == "" {
		uri = "/"
	}
	headers, err := canonicalHeaders(r, signedHeaders)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{
		r.Method,
		uri,
		canonicalQuery(r),
		headers,
		strings.ToLower(signedHeaders),
		payloadHash,
	}, "\n"), nil
}

func canonicalHeaders(r *http.Request, signedHeaders string) (string, *AuthError) {
	names := strings.Split(strings.ToLower(signedHeaders), ";")
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		if name == "" {
			continue
		}
		var value string
		switch name {
		case "host":
			value = r.Host
		case "content-length":
			if r.ContentLength >= 0 {
				value = strconv.FormatInt(r.ContentLength, 10)
			}
		default:
			value = strings.Join(r.Header.Values(name), ",")
		}
		value = strings.Join(strings.Fields(value), " ")
		b.WriteString(name)
		b.WriteString(":")
		b.WriteString(value)
		b.WriteString("\n")
	}
	return b.String(), nil
}

// canonicalQuery re-encodes and sorts query parameters per AWS rules. It works
// from the raw query so a literal '+' stays a plus (Go's Query would decode it
// as a space) and percent-escaped slashes/Unicode are decoded exactly once.
func canonicalQuery(r *http.Request) string {
	type kv struct{ k, v string }
	var pairs []kv
	raw := r.URL.RawQuery
	if raw != "" {
		for part := range strings.SplitSeq(raw, "&") {
			if part == "" {
				continue
			}
			k, v, _ := strings.Cut(part, "=")
			key, err := url.PathUnescape(k)
			if err != nil {
				key = k
			}
			value, err := url.PathUnescape(v)
			if err != nil {
				value = v
			}
			if key == "X-Amz-Signature" {
				continue
			}
			pairs = append(pairs, kv{awsEncode(key), awsEncode(value)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k == pairs[j].k {
			return pairs[i].v < pairs[j].v
		}
		return pairs[i].k < pairs[j].k
	})
	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(p.k)
		b.WriteByte('=')
		b.WriteString(p.v)
	}
	return b.String()
}

// encodeQuery builds a query string using the exact AWS escaping rules.
func encodeQuery(q url.Values) string {
	type kv struct{ k, v string }
	var pairs []kv
	for k, vs := range q {
		for _, v := range vs {
			pairs = append(pairs, kv{awsEncode(k), awsEncode(v)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k == pairs[j].k {
			return pairs[i].v < pairs[j].v
		}
		return pairs[i].k < pairs[j].k
	})
	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(p.k)
		b.WriteByte('=')
		b.WriteString(p.v)
	}
	return b.String()
}

// awsEncode implements the RFC 3986 encoding required by SigV4.
func awsEncode(s string) string { return pctenc.Encode(s, false) }

func signingKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	return hmacSHA256(kService, "aws4_request")
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func sha256Hex(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

// SignQuery appends a presigned GET signature to rawURL.
func SignQuery(rawURL, accessKey, secret, region string, expires time.Time) (string, error) {
	return SignQueryMethod(rawURL, accessKey, secret, region, http.MethodGet, expires)
}

// SignQueryMethod appends a presigned signature for method to rawURL.
func SignQueryMethod(rawURL, accessKey, secret, region, method string, expires time.Time) (string, error) {
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	if !expires.After(now) {
		return "", fmt.Errorf("presigned URL expiry must be in the future")
	}
	seconds := max(int64(expires.Sub(now).Seconds()), 1)
	if seconds > 604800 {
		return "", fmt.Errorf("presigned URL expiry cannot exceed 7 days")
	}
	datetime := now.Format("20060102T150405Z")
	date := datetime[:8]
	existing := strings.TrimSuffix(req.URL.RawQuery, "&")
	q := url.Values{}
	q.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	q.Set("X-Amz-Credential", accessKey+"/"+date+"/"+region+"/s3/aws4_request")
	q.Set("X-Amz-Date", datetime)
	q.Set("X-Amz-Expires", strconv.FormatInt(seconds, 10))
	q.Set("X-Amz-SignedHeaders", "host")
	signedQuery := encodeQuery(q)
	if existing != "" {
		signedQuery = existing + "&" + signedQuery
	}
	req.URL.RawQuery = signedQuery
	canonical, aerr := canonicalRequest(req, "host", "UNSIGNED-PAYLOAD")
	if aerr != nil {
		return "", aerr
	}
	scope := date + "/" + region + "/s3/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + datetime + "\n" + scope + "\n" + sha256Hex(canonical)
	sig := hex.EncodeToString(hmacSHA256(signingKey(secret, date, region, "s3"), stringToSign))
	q.Set("X-Amz-Signature", sig)
	finalQuery := encodeQuery(q)
	if existing != "" {
		finalQuery = existing + "&" + finalQuery
	}
	req.URL.RawQuery = finalQuery
	return req.URL.String(), nil
}
