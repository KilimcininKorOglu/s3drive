package s3

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

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
	authz := r.Header.Get("Authorization")
	if authz == "" {
		return nil, authErr("AccessDenied", "anonymous request is not allowed")
	}
	if !strings.HasPrefix(authz, "AWS4-HMAC-SHA256 ") {
		return nil, authErr("InvalidRequest", "unsupported authorization algorithm")
	}
	fields := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(authz, "AWS4-HMAC-SHA256 "), ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok {
			fields[k] = v
		}
	}
	credential := fields["Credential"]
	signedHeaders := fields["SignedHeaders"]
	signature := fields["Signature"]
	if credential == "" || signedHeaders == "" || signature == "" {
		return nil, authErr("InvalidRequest", "malformed Authorization header")
	}
	accessKey, _, date, region, ok := parseCredential(credential)
	if !ok {
		return nil, authErr("InvalidRequest", "malformed credential scope")
	}
	_ = date

	datetime := r.Header.Get("X-Amz-Date")
	if datetime == "" {
		datetime = r.Header.Get("Date")
	}
	t, err := time.Parse("20060102T150405Z", datetime)
	if err != nil {
		return nil, authErr("RequestTimeTooSkewed", "missing or invalid x-amz-date")
	}
	if d := now.Sub(t); d > 15*time.Minute || d < -15*time.Minute {
		return nil, authErr("RequestTimeTooSkewed", "request time is too far from server time")
	}

	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		payloadHash = "UNSIGNED-PAYLOAD"
	}

	secret, active, err := a.Store.GetAccessKeySecret(r.Context(), accessKey)
	if err != nil || !active {
		return nil, authErr("InvalidAccessKeyId", "the access key does not exist or is disabled")
	}

	canonical, aerr := canonicalRequest(r, signedHeaders, payloadHash)
	if aerr != nil {
		return nil, aerr
	}
	scopeLine := date + "/" + region + "/s3/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + datetime + "\n" + scopeLine + "\n" + sha256Hex(canonical)
	key := signingKey(secret, date, region, "s3")
	expected := hex.EncodeToString(hmacSHA256(key, stringToSign))
	if subtle.ConstantTimeCompare([]byte(expected), []byte(strings.ToLower(signature))) != 1 {
		return nil, authErr("SignatureDoesNotMatch", "the request signature we calculated does not match the signature you provided")
	}
	a.Store.TouchAccessKey(r.Context(), accessKey)
	return &Auth{
		AccessKey: accessKey, PayloadHash: payloadHash, Signature: strings.ToLower(signature),
		SigningKey: key, Scope: scopeLine, DateTime: datetime,
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
	accessKey, _, date, region, ok := parseCredential(credential)
	if !ok {
		return nil, authErr("InvalidRequest", "malformed credential scope")
	}
	t, err := time.Parse("20060102T150405Z", datetime)
	if err != nil {
		return nil, authErr("RequestTimeTooSkewed", "invalid X-Amz-Date")
	}
	expires, err := strconv.ParseInt(q.Get("X-Amz-Expires"), 10, 64)
	if err != nil || expires < 1 || expires > 604800 {
		return nil, authErr("InvalidRequest", "X-Amz-Expires must be between 1 and 604800 seconds")
	}
	if now.After(t.Add(time.Duration(expires) * time.Second)) {
		return nil, authErr("AccessDenied", "request has expired")
	}
	if t.After(now.Add(15 * time.Minute)) {
		return nil, authErr("RequestTimeTooSkewed", "presigned request is from the future")
	}
	payloadHash := q.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		payloadHash = "UNSIGNED-PAYLOAD"
	}
	secret, active, err := a.Store.GetAccessKeySecret(r.Context(), accessKey)
	if err != nil || !active {
		return nil, authErr("InvalidAccessKeyId", "the access key does not exist or is disabled")
	}
	canonical, aerr := canonicalRequest(r, signedHeaders, payloadHash)
	if aerr != nil {
		return nil, aerr
	}
	scopeLine := date + "/" + region + "/s3/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + datetime + "\n" + scopeLine + "\n" + sha256Hex(canonical)
	key := signingKey(secret, date, region, "s3")
	expected := hex.EncodeToString(hmacSHA256(key, stringToSign))
	if subtle.ConstantTimeCompare([]byte(expected), []byte(strings.ToLower(signature))) != 1 {
		return nil, authErr("SignatureDoesNotMatch", "the request signature we calculated does not match the signature you provided")
	}
	a.Store.TouchAccessKey(r.Context(), accessKey)
	return &Auth{
		AccessKey: accessKey, PayloadHash: payloadHash, Signature: strings.ToLower(signature),
		SigningKey: key, Scope: scopeLine, DateTime: datetime, Presigned: true,
	}, nil
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

// canonicalQuery re-encodes and sorts query parameters per AWS rules.
func canonicalQuery(r *http.Request) string {
	values := r.URL.Query()
	type kv struct{ k, v string }
	var pairs []kv
	for k, vs := range values {
		if k == "X-Amz-Signature" {
			continue
		}
		encodedKey := awsEncode(k)
		if len(vs) == 0 {
			pairs = append(pairs, kv{encodedKey, ""})
			continue
		}
		for _, v := range vs {
			pairs = append(pairs, kv{encodedKey, awsEncode(v)})
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
func awsEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.' || ch == '~' {
			b.WriteByte(ch)
		} else {
			fmt.Fprintf(&b, "%%%02X", ch)
		}
	}
	return b.String()
}

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

// SignQuery appends a presigned signature to rawURL.
func SignQuery(rawURL, accessKey, secret, region string, expires time.Time) (string, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	t := expires.UTC()
	datetime := t.Format("20060102T150405Z")
	date := datetime[:8]
	q := req.URL.Query()
	q.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	q.Set("X-Amz-Credential", accessKey+"/"+date+"/"+region+"/s3/aws4_request")
	q.Set("X-Amz-Date", datetime)
	q.Set("X-Amz-Expires", strconv.FormatInt(int64(time.Until(t).Seconds()), 10))
	q.Set("X-Amz-SignedHeaders", "host")
	req.URL.RawQuery = q.Encode()
	canonical, aerr := canonicalRequest(req, "host", "UNSIGNED-PAYLOAD")
	if aerr != nil {
		return "", aerr
	}
	scope := date + "/" + region + "/s3/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + datetime + "\n" + scope + "\n" + sha256Hex(canonical)
	sig := hex.EncodeToString(hmacSHA256(signingKey(secret, date, region, "s3"), stringToSign))
	q.Set("X-Amz-Signature", sig)
	req.URL.RawQuery = q.Encode()
	return req.URL.String(), nil
}
