// Package s3 exposes the S3-compatible HTTP API.
package s3

import (
	"bytes"
	"cmp"
	"context"
	"crypto/md5" // #nosec G501 -- S3 Content-MD5 check, not a security primitive
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"s3drive/internal/drive"
	"s3drive/internal/google"
	"s3drive/internal/store"
)

// Server is the S3 endpoint.
type Server struct {
	Store    *store.Store
	Svc      *drive.Service
	Auth     *Authenticator
	Log      *slog.Logger
	SpoolDir string
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqID := store.NewID()
	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	sw.Header().Set("x-amz-request-id", reqID)
	sw.Header().Set("Server", "s3drive")

	cfg, cfgErr := s.Svc.LoadSettings(r.Context())
	if cfgErr != nil {
		s.Log.Error("load settings", "err", cfgErr)
	}
	s.applyCORS(sw, r, cfg)
	if r.Method == http.MethodOptions {
		sw.WriteHeader(http.StatusNoContent)
		return
	}

	bucket, key := splitPath(r)
	oc := &opCtx{
		w: sw, r: r, reqID: reqID, cfg: cfg, bucket: bucket, key: key,
		op: opName(r, bucket, key), started: time.Now(),
	}
	defer oc.record(s)

	auth, aerr := s.authenticate(r, bucket, key)
	if aerr != nil {
		writeS3Error(oc.w, r, reqID, aerr.Code, aerr.Message, aerr.Status)
		return
	}
	if auth != nil {
		oc.accessKey = auth.AccessKey
		oc.keyPolicy = auth.Key
		if !s.authorize(oc, auth) {
			return
		}
		if !validPayloadHash(auth.PayloadHash) {
			writeS3Error(oc.w, r, reqID, "InvalidArgument", "unsupported x-amz-content-sha256", http.StatusBadRequest)
			return
		}
		r.Body = newPayloadReader(r.Body, auth, r.Header.Get("x-amz-trailer"))
		r.Body = verifyPayloadHash(r.Body, auth.PayloadHash)
		defer func() { _ = r.Body.Close() }() // request body; the server closes the connection side
	}

	switch {
	case bucket == "":
		if r.Method != http.MethodGet {
			s.methodNotAllowed(oc)
			return
		}
		s.listBuckets(oc)
	case key == "":
		s.bucketRequest(oc)
	default:
		s.objectRequest(oc)
	}
}

// authenticate enforces SigV4, except for anonymous GET/HEAD on a public
// bucket.
func (s *Server) authenticate(r *http.Request, bucket, key string) (*Auth, *AuthError) {
	hasAuth := r.Header.Get("Authorization") != "" || r.URL.Query().Get("X-Amz-Algorithm") != ""
	if hasAuth {
		return s.Auth.Authenticate(r)
	}
	if bucket == "" || key == "" || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		return nil, authErr("AccessDenied", "anonymous request is not allowed")
	}
	ref, err := s.Svc.Bucket(r.Context(), bucket)
	if err != nil || !ref.PublicRead {
		return nil, authErr("AccessDenied", "anonymous request is not allowed")
	}
	return nil, nil
}

// authorize applies the access key's bucket/prefix/read-write policy.
func (s *Server) authorize(o *opCtx, a *Auth) bool {
	k := a.Key
	if k == nil {
		return true
	}
	read := o.r.Method == http.MethodGet || o.r.Method == http.MethodHead
	switch {
	case o.bucket == "":
		return read
	case o.key == "":
		return authorizeBucket(o, k, read)
	case read:
		return k.CanRead(o.bucket, o.key) || denyKey(o)
	}
	return k.CanWrite(o.bucket, o.key) || denyKey(o)
}

// denyKey writes AccessDenied for a key policy violation and returns false.
func denyKey(o *opCtx) bool {
	writeS3Error(o.w, o.r, o.reqID, "AccessDenied", "this access key is not allowed to perform this operation", http.StatusForbidden)
	return false
}

func authorizeBucket(o *opCtx, k *store.AccessKey, read bool) bool {
	if read {
		return authorizeBucketRead(o, k)
	}
	if o.r.Method == http.MethodPut || o.r.Method == http.MethodDelete {
		return k.CanWriteBucket(o.bucket) || denyKey(o)
	}
	// DeleteObjects checks each key individually.
	if hasQuery(o.r, "delete") {
		return k.Bucket == "" || k.Bucket == o.bucket
	}
	return denyKey(o)
}

func authorizeBucketRead(o *opCtx, k *store.AccessKey) bool {
	if k.Bucket != "" && k.Bucket != o.bucket {
		return denyKey(o)
	}
	q := o.r.URL.Query()
	listing := q.Get("uploads") != "" || q.Get("list-type") == "2" || o.r.Method == http.MethodGet
	if k.Prefix == "" || !listing {
		return true
	}
	return scopeListPrefix(o, k.Prefix)
}

// scopeListPrefix narrows a listing to the key's prefix: an empty prefix is
// replaced with it and a prefix outside it is denied.
func scopeListPrefix(o *opCtx, keyPrefix string) bool {
	q := o.r.URL.Query()
	p := q.Get("prefix")
	if p == "" {
		q.Set("prefix", keyPrefix)
		o.r.URL.RawQuery = q.Encode()
		return true
	}
	return strings.HasPrefix(p, keyPrefix) || denyKey(o)
}

type opCtx struct {
	w         *statusWriter
	r         *http.Request
	reqID     string
	cfg       drive.Settings
	bucket    string
	key       string
	op        string
	acctID    string
	accessKey string
	keyPolicy *store.AccessKey
	bytes     int64
	started   time.Time
}

func (o *opCtx) record(s *Server) {
	status := o.w.status
	if o.op == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Store.AddEvent(ctx, store.Event{
		Op: o.op, Bucket: o.bucket, Key: o.key, AccountID: o.acctID, AccessKey: o.accessKey,
		Bytes: o.bytes, Status: status, MS: time.Since(o.started).Milliseconds(),
	}); err != nil {
		s.Log.Warn("record audit event", "op", o.op, "err", err)
	}
	if status >= 500 {
		s.Log.Warn("s3 request failed", "op", o.op, "bucket", o.bucket, "key", o.key, "status", status, "ms", time.Since(o.started).Milliseconds())
	}
}

// ---------------------------------------------------------------------------
// Bucket and service level operations

func (s *Server) bucketRequest(o *opCtx) {
	switch o.r.Method {
	case http.MethodHead:
		s.headBucket(o)
	case http.MethodPut:
		s.unlessSubresource(o, s.createBucket)
	case http.MethodDelete:
		s.unlessSubresource(o, s.deleteBucket)
	case http.MethodGet:
		s.unlessSubresource(o, s.bucketGet)
	case http.MethodPost:
		if hasQuery(o.r, "delete") {
			s.deleteObjects(o)
			return
		}
		s.unlessSubresource(o, s.methodNotAllowed)
	default:
		s.methodNotAllowed(o)
	}
}

// unlessSubresource runs handle when the request is not a bucket
// subresource (acl, cors, policy, ...), which bucketSubresource serves.
func (s *Server) unlessSubresource(o *opCtx, handle func(*opCtx)) {
	if !s.bucketSubresource(o) {
		handle(o)
	}
}

func (s *Server) bucketGet(o *opCtx) {
	if o.r.URL.Query().Get("uploads") != "" || hasQuery(o.r, "uploads") {
		s.listMultipartUploads(o)
		return
	}
	s.listObjects(o)
}

func (s *Server) objectRequest(o *opCtx) {
	if hasQuery(o.r, "uploads") && o.r.Method == http.MethodPost {
		s.createMultipartUpload(o)
		return
	}
	if o.r.URL.Query().Get("uploadId") != "" {
		s.multipartRequest(o)
		return
	}
	if s.objectSubresource(o) {
		return
	}
	s.plainObjectRequest(o)
}

func (s *Server) multipartRequest(o *opCtx) {
	switch o.r.Method {
	case http.MethodPut:
		s.uploadPart(o)
	case http.MethodPost:
		s.completeMultipartUpload(o)
	case http.MethodDelete:
		s.abortMultipartUpload(o)
	case http.MethodGet:
		s.listParts(o)
	default:
		s.methodNotAllowed(o)
	}
}

func (s *Server) plainObjectRequest(o *opCtx) {
	switch o.r.Method {
	case http.MethodGet:
		s.getObject(o)
	case http.MethodHead:
		s.headObject(o)
	case http.MethodPut:
		if o.r.Header.Get("x-amz-copy-source") != "" {
			s.copyObject(o)
		} else {
			s.putObject(o)
		}
	case http.MethodDelete:
		s.deleteObject(o)
	case http.MethodPost:
		s.methodNotAllowed(o)
	default:
		s.methodNotAllowed(o)
	}
}

func (s *Server) listBuckets(o *opCtx) {
	buckets, err := s.Svc.ListBuckets(o.r.Context())
	if err != nil {
		s.fail(o, err)
		return
	}
	out := listAllBucketsResult{
		Xmlns: xmlNS,
		Owner: owner{ID: "s3drive", DisplayName: "s3drive"},
	}
	for _, b := range buckets {
		if o.keyPolicy != nil && o.keyPolicy.Bucket != "" && b.Name != o.keyPolicy.Bucket {
			continue
		}
		created := time.Now().UTC()
		if b.Row != nil && !b.Row.CreatedAt.IsZero() {
			created = b.Row.CreatedAt
		}
		out.Buckets.Bucket = append(out.Buckets.Bucket, bucketEntry{Name: b.Name, CreationDate: created.UTC().Format(time.RFC3339)})
	}
	writeXML(o.w, http.StatusOK, out)
}

func (s *Server) createBucket(o *opCtx) {
	account := o.r.Header.Get("x-s3drive-account")
	if account == "" {
		account = o.r.URL.Query().Get("account")
	}
	ref, err := s.Svc.CreateBucket(o.r.Context(), o.bucket, account)
	if err != nil {
		s.fail(o, err)
		return
	}
	o.acctID = ref.Account.ID
	o.w.Header().Set("Location", "/"+ref.Name)
	o.w.WriteHeader(http.StatusOK)
}

func (s *Server) headBucket(o *opCtx) {
	ref, err := s.Svc.Bucket(o.r.Context(), o.bucket)
	if err != nil {
		s.fail(o, err)
		return
	}
	if ref.Account != nil {
		o.acctID = ref.Account.ID
	}
	o.w.Header().Set("x-amz-bucket-region", o.cfg.Region)
	o.w.WriteHeader(http.StatusOK)
}

func (s *Server) deleteBucket(o *opCtx) {
	if err := s.Svc.DeleteBucket(o.r.Context(), o.bucket); err != nil {
		s.fail(o, err)
		return
	}
	o.w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listObjects(o *opCtx) {
	q := o.r.URL.Query()
	p, problem := parseListParams(q)
	if problem != "" {
		writeS3Error(o.w, o.r, o.reqID, "InvalidArgument", problem, http.StatusBadRequest)
		return
	}
	res, err := s.Svc.List(o.r.Context(), o.bucket, p.prefix, p.delimiter, p.maxKeys, p.after)
	if err != nil {
		s.fail(o, err)
		return
	}
	ref, _ := s.Svc.Bucket(o.r.Context(), o.bucket) // audit attribution only; List already resolved it
	if ref != nil && ref.Account != nil {
		o.acctID = ref.Account.ID
	}
	out := listBucketResult{
		Xmlns:        xmlNS,
		Name:         o.bucket,
		Prefix:       encodeKey(p.prefix, p.encoding),
		Delimiter:    encodeKey(p.delimiter, p.encoding),
		MaxKeys:      p.maxKeys,
		IsTruncated:  res.IsTruncated,
		EncodingType: p.encoding,
		Contents:     listContents(res.Objects, p.encoding, q.Get("fetch-owner") == "true"),
	}
	for _, cp := range res.CommonPrefixes {
		out.CommonPrefixes = append(out.CommonPrefixes, commonPrefix{Prefix: encodeKey(cp, p.encoding)})
	}
	setListPaging(&out, p, res, q)
	writeXML(o.w, http.StatusOK, out)
}

// listParams holds the validated ListObjects (V1/V2) query.
type listParams struct {
	prefix, delimiter, encoding, after string
	maxKeys                            int
	v2                                 bool
}

// parseListParams validates the query; problem is the S3 error message for
// an invalid value.
func parseListParams(q url.Values) (p listParams, problem string) {
	p = listParams{prefix: q.Get("prefix"), delimiter: q.Get("delimiter"), encoding: q.Get("encoding-type"), v2: q.Get("list-type") == "2"}
	if p.encoding != "" && p.encoding != "url" {
		return p, "invalid encoding-type"
	}
	var ok bool
	if p.maxKeys, ok = parseMaxKeys(q.Get("max-keys")); !ok {
		return p, "invalid max-keys"
	}
	if p.after, ok = listStart(q, p.v2); !ok {
		return p, "invalid continuation token"
	}
	return p, ""
}

// parseMaxKeys defaults to and caps at 1000.
func parseMaxKeys(v string) (int, bool) {
	if v == "" {
		return 1000, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, false
	}
	return min(n, 1000), true
}

// listStart returns the key to list after: the decoded V2 continuation
// token, else V2 start-after, else the V1 marker.
func listStart(q url.Values, v2 bool) (string, bool) {
	if !v2 {
		return q.Get("marker"), true
	}
	tok := q.Get("continuation-token")
	if tok == "" {
		return q.Get("start-after"), true
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return "", false
	}
	return string(raw), true
}

func listContents(objects []drive.Object, encoding string, fetchOwner bool) []listObject {
	var out []listObject
	for _, obj := range objects {
		item := listObject{
			Key:          encodeKey(obj.Key, encoding),
			LastModified: xmlTime(obj.Modified),
			ETag:         quoteETag(obj.ETag),
			Size:         obj.Size,
			StorageClass: cmp.Or(obj.StorageClass, "STANDARD"),
		}
		if fetchOwner {
			item.Owner = &owner{ID: cmp.Or(obj.AccountID, "s3drive"), DisplayName: obj.AccountMail}
		}
		out = append(out, item)
	}
	return out
}

func setListPaging(out *listBucketResult, p listParams, res *drive.ListResult, q url.Values) {
	if !p.v2 {
		out.Marker = encodeKey(p.after, p.encoding)
		if res.IsTruncated {
			out.NextMarker = encodeKey(res.NextAfter, p.encoding)
		}
		return
	}
	keyCount := len(res.Objects) + len(res.CommonPrefixes)
	out.KeyCount = &keyCount
	out.ContinuationToken = q.Get("continuation-token")
	out.StartAfter = q.Get("start-after")
	if res.IsTruncated {
		out.NextContinuationToken = base64.RawURLEncoding.EncodeToString([]byte(res.NextAfter))
	}
}

// ---------------------------------------------------------------------------
// Object operations

func (s *Server) putObject(o *opCtx) {
	if strings.HasSuffix(o.key, "/") {
		s.putFolderMarker(o)
		return
	}
	expected, ok := s.expectedPutChecksums(o)
	if !ok || !s.checkWriteConditions(o) {
		return
	}
	contentType := cmp.Or(o.r.Header.Get("Content-Type"), "application/octet-stream")
	storageClass := cmp.Or(strings.ToUpper(strings.TrimSpace(o.r.Header.Get("x-amz-storage-class"))), "STANDARD")
	res, err := s.Svc.PutChecked(o.r.Context(), o.bucket, o.key, contentType, o.r.Body, expected)
	if err != nil {
		s.fail(o, err)
		return
	}
	meta := store.ObjectMeta{
		Bucket: o.bucket, Key: o.key, ETag: res.ETag, ContentType: contentType,
		StorageClass: storageClass, Metadata: userMetadataJSON(o.r),
		Checksum: drive.ChecksumHeader(expected),
	}
	if err := s.Svc.SetObjectMeta(o.r.Context(), meta); err != nil {
		s.fail(o, fmt.Errorf("store object metadata: %w", err))
		return
	}
	o.acctID, o.bytes = res.AccountID, res.Size
	setChecksumResponse(o, meta.Checksum)
	o.w.Header().Set("ETag", quoteETag(res.ETag))
	o.w.WriteHeader(http.StatusOK)
}

// checkWriteConditions implements If-None-Match: * and If-Match for writes.
// putFolderMarker stores an empty "key/" object as a Drive folder.
func (s *Server) putFolderMarker(o *opCtx) {
	if o.r.ContentLength > 0 {
		writeS3Error(o.w, o.r, o.reqID, "InvalidArgument", "folder markers must be empty", http.StatusBadRequest)
		return
	}
	if err := s.Svc.CreateFolder(o.r.Context(), o.bucket, o.key); err != nil {
		s.fail(o, err)
		return
	}
	o.w.Header().Set("ETag", quoteETag("d41d8cd98f00b204e9800998ecf8427e"))
	o.w.WriteHeader(http.StatusOK)
}

// expectedPutChecksums collects the checksums the client asked us to verify,
// including Content-MD5. It writes the error response itself.
func (s *Server) expectedPutChecksums(o *opCtx) (map[string]string, bool) {
	expectedMD5, aerr := contentMD5(o.r)
	if aerr != nil {
		writeS3Error(o.w, o.r, o.reqID, aerr.Code, aerr.Message, aerr.Status)
		return nil, false
	}
	expected := expectedChecksums(o.r)
	if expectedMD5 != "" {
		expected["md5"] = expectedMD5
	}
	return expected, true
}

func (s *Server) checkWriteConditions(o *opCtx) bool {
	ifNone := o.r.Header.Get("If-None-Match")
	ifMatch := o.r.Header.Get("If-Match")
	if ifNone == "" && ifMatch == "" {
		return true
	}
	obj, _, err := s.Svc.Stat(o.r.Context(), o.bucket, o.key)
	if err != nil && !drive.IsNotFound(err) {
		s.fail(o, err)
		return false
	}
	etag := ""
	if err == nil {
		etag = obj.ETag
	}
	if !writePreconditionsHold(ifNone, ifMatch, err == nil, etag) {
		writeS3Error(o.w, o.r, o.reqID, "PreconditionFailed", "At least one of the pre-conditions you specified did not hold", http.StatusPreconditionFailed)
		return false
	}
	return true
}

// writePreconditionsHold applies If-None-Match: * (create only) and If-Match
// (the existing ETag, or * for any existing object).
func writePreconditionsHold(ifNone, ifMatch string, exists bool, etag string) bool {
	if ifNone == "*" && exists {
		return false
	}
	if ifMatch == "" {
		return true
	}
	return exists && (ifMatch == "*" || etagMatches(ifMatch, etag))
}

func expectedChecksums(r *http.Request) map[string]string {
	out := map[string]string{}
	for _, alg := range []string{"sha256", "sha1", "crc32", "crc32c"} {
		if v := r.Header.Get("x-amz-checksum-" + alg); v != "" {
			out[alg] = v
		}
	}
	return out
}

func userMetadataJSON(r *http.Request) string {
	meta := map[string]string{}
	for k, vs := range r.Header {
		lk := strings.ToLower(k)
		if after, ok := strings.CutPrefix(lk, "x-amz-meta-"); ok {
			meta[after] = strings.Join(vs, ",")
		}
	}
	if len(meta) == 0 {
		return ""
	}
	b, _ := json.Marshal(meta)
	return string(b)
}

func setChecksumResponse(o *opCtx, checksum string) {
	for part := range strings.SplitSeq(checksum, ";") {
		k, v, ok := strings.Cut(part, "=")
		if ok && v != "" {
			o.w.Header().Set(k, v)
		}
	}
}

func (s *Server) getObject(o *opCtx) {
	rangeHeader, ok := s.resolveRange(o)
	if !ok {
		return
	}
	obj, err := s.Svc.Get(o.r.Context(), o.bucket, o.key, rangeHeader)
	if err != nil {
		s.fail(o, err)
		return
	}
	defer func() { _ = obj.Body.Close() }() // read side; copy errors are reported below
	o.acctID = acctIDOf(obj.Account)
	o.bytes = obj.Object.Size

	if done := checkConditions(o, obj); done {
		return
	}
	setObjectHeaders(o, obj)
	status := http.StatusOK
	if obj.ContentRange != "" {
		status = http.StatusPartialContent
	}
	applyResponseOverrides(o)
	o.w.WriteHeader(status)
	n, err := io.Copy(o.w, obj.Body)
	o.bytes = n
	if err != nil {
		// Headers are sent; the client sees a short body. Usually a disconnect.
		s.Log.Debug("stream object body", "bucket", o.bucket, "key", o.key, "bytes", n, "err", err)
	}
}

// resolveRange validates the Range header against the object size. It
// drops the range when If-Range does not match and writes 416 itself.
func (s *Server) resolveRange(o *opCtx) (string, bool) {
	rangeHeader := o.r.Header.Get("Range")
	if rangeHeader == "" {
		return "", true
	}
	stat, _, err := s.Svc.Stat(o.r.Context(), o.bucket, o.key)
	if err != nil {
		s.fail(o, err)
		return "", false
	}
	if ifRange := o.r.Header.Get("If-Range"); ifRange != "" && !ifRangeMatches(ifRange, stat.ETag, stat.Modified) {
		return "", true
	}
	if _, _, _, ok := parseByteRange(rangeHeader, stat.Size); !ok {
		o.w.Header().Set("Content-Range", "bytes */"+strconv.FormatInt(stat.Size, 10))
		writeS3Error(o.w, o.r, o.reqID, "InvalidRange", "The requested range is not satisfiable", http.StatusRequestedRangeNotSatisfiable)
		return "", false
	}
	return rangeHeader, true
}

// applyResponseOverrides honors the response-* query overrides S3 allows
// on GET (typically from presigned URLs).
func applyResponseOverrides(o *opCtx) {
	q := o.r.URL.Query()
	for param, header := range map[string]string{
		"response-content-type":        "Content-Type",
		"response-content-disposition": "Content-Disposition",
		"response-cache-control":       "Cache-Control",
	} {
		if v := q.Get(param); v != "" {
			o.w.Header().Set(header, v)
		}
	}
}

func (s *Server) headObject(o *opCtx) {
	obj, acct, err := s.Svc.Stat(o.r.Context(), o.bucket, o.key)
	if err != nil {
		s.fail(o, err)
		return
	}
	o.acctID = acctIDOf(acct)
	o.bytes = obj.Size
	reader := &drive.ObjectReader{Object: *obj}
	if done := checkConditions(o, reader); done {
		return
	}
	rangeHeader := o.r.Header.Get("Range")
	if rangeHeader != "" && ifRangeMatches(o.r.Header.Get("If-Range"), obj.ETag, obj.Modified) {
		start, end, _, ok := parseByteRange(rangeHeader, obj.Size)
		if !ok {
			o.w.Header().Set("Content-Range", "bytes */"+strconv.FormatInt(obj.Size, 10))
			writeS3Error(o.w, o.r, o.reqID, "InvalidRange", "The requested range is not satisfiable", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		setObjectHeaders(o, reader)
		o.w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
		o.w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, obj.Size))
		o.w.WriteHeader(http.StatusPartialContent)
		return
	}
	setObjectHeaders(o, reader)
	o.w.WriteHeader(http.StatusOK)
}

// ifRangeMatches reports whether an If-Range validator still matches. An
// empty validator is treated as a match.
func ifRangeMatches(value, etag string, modified time.Time) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	if strings.HasPrefix(value, `"`) || strings.HasPrefix(value, "W/") {
		return etagMatches(value, etag)
	}
	t, err := http.ParseTime(value)
	return err == nil && !modified.After(t)
}

// parseByteRange parses one HTTP byte range. It returns inclusive bounds and
// satisfiable=false for syntactically valid but out-of-bounds ranges.
func parseByteRange(value string, size int64) (start, end int64, length int64, ok bool) {
	if !strings.HasPrefix(value, "bytes=") || strings.Contains(value, ",") || size < 0 {
		return 0, 0, 0, false
	}
	spec := strings.TrimSpace(strings.TrimPrefix(value, "bytes="))
	a, b, hasDash := strings.Cut(spec, "-")
	if !hasDash {
		return 0, 0, 0, false
	}
	if a == "" {
		return suffixRange(strings.TrimSpace(b), size)
	}
	return boundedRange(a, strings.TrimSpace(b), size)
}

// suffixRange resolves "-N": the last N bytes, clamped to the object size.
func suffixRange(n string, size int64) (start, end, length int64, ok bool) {
	count, err := strconv.ParseInt(n, 10, 64)
	if err != nil || count <= 0 {
		return 0, 0, 0, false
	}
	count = min(count, size)
	if count == 0 {
		return 0, 0, 0, false
	}
	return size - count, size - 1, count, true
}

// boundedRange resolves "first-" and "first-last", clamping last to the end.
func boundedRange(first, last string, size int64) (start, end, length int64, ok bool) {
	start, err := strconv.ParseInt(first, 10, 64)
	if err != nil || start < 0 || start >= size {
		return 0, 0, 0, false
	}
	end = size - 1
	if last != "" {
		end, err = strconv.ParseInt(last, 10, 64)
		if err != nil || end < start {
			return 0, 0, 0, false
		}
		end = min(end, size-1)
	}
	return start, end, end - start + 1, true
}

func setObjectHeaders(o *opCtx, obj *drive.ObjectReader) {
	h := o.w.Header()
	ct := obj.Object.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	h.Set("Content-Type", ct)
	h.Set("ETag", quoteETag(obj.Object.ETag))
	if !obj.Object.Modified.IsZero() {
		h.Set("Last-Modified", obj.Object.Modified.UTC().Format(http.TimeFormat))
	}
	h.Set("Accept-Ranges", "bytes")
	h.Set("Content-Length", strconv.FormatInt(obj.Object.Size, 10))
	if obj.Object.StorageClass != "" && obj.Object.StorageClass != "STANDARD" {
		h.Set("x-amz-storage-class", obj.Object.StorageClass)
	}
	for k, v := range obj.Object.Metadata {
		h.Set("x-amz-meta-"+k, v)
	}
	for part := range strings.SplitSeq(obj.Object.Checksum, ";") {
		k, v, ok := strings.Cut(part, "=")
		if ok && v != "" {
			h.Set(k, v)
		}
	}
	if obj.ContentRange != "" {
		h.Set("Content-Range", obj.ContentRange)
	}
}

// checkConditions implements the usual S3 conditional GET headers.
func checkConditions(o *opCtx, obj *drive.ObjectReader) bool {
	h := o.r.Header
	if v := h.Get("If-Match"); v != "" && v != "*" && !etagMatches(v, obj.Object.ETag) {
		writeS3Error(o.w, o.r, o.reqID, "PreconditionFailed", "At least one of the pre-conditions you specified did not hold", http.StatusPreconditionFailed)
		return true
	}
	if v := h.Get("If-None-Match"); v != "" && (v == "*" || etagMatches(v, obj.Object.ETag)) {
		setObjectHeaders(o, obj)
		o.w.WriteHeader(http.StatusNotModified)
		return true
	}
	if v := h.Get("If-Modified-Since"); v != "" {
		if t, err := http.ParseTime(v); err == nil && !obj.Object.Modified.After(t) {
			setObjectHeaders(o, obj)
			o.w.WriteHeader(http.StatusNotModified)
			return true
		}
	}
	if v := h.Get("If-Unmodified-Since"); v != "" {
		if t, err := http.ParseTime(v); err == nil && obj.Object.Modified.After(t) {
			writeS3Error(o.w, o.r, o.reqID, "PreconditionFailed", "the object was modified", http.StatusPreconditionFailed)
			return true
		}
	}
	return false
}

func etagMatches(header, etag string) bool {
	for candidate := range strings.SplitSeq(header, ",") {
		candidate = strings.TrimSpace(candidate)
		candidate = strings.Trim(candidate, `"`)
		if candidate == etag || candidate == "*" {
			return true
		}
	}
	return false
}

func (s *Server) deleteObject(o *opCtx) {
	err := s.Svc.Delete(o.r.Context(), o.bucket, o.key)
	if err != nil && !drive.IsNotFound(err) {
		s.fail(o, err)
		return
	}
	o.w.WriteHeader(http.StatusNoContent)
}

func (s *Server) copyObject(o *opCtx) {
	raw := o.r.Header.Get("x-amz-copy-source")
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		raw = raw[:i]
	}
	decoded, err := url.PathUnescape(strings.TrimPrefix(raw, "/"))
	if err != nil {
		writeS3Error(o.w, o.r, o.reqID, "InvalidArgument", "invalid x-amz-copy-source", http.StatusBadRequest)
		return
	}
	srcBucket, srcKey := splitFirst(decoded)
	if srcBucket == "" || srcKey == "" {
		writeS3Error(o.w, o.r, o.reqID, "InvalidArgument", "invalid x-amz-copy-source", http.StatusBadRequest)
		return
	}
	if o.keyPolicy != nil && !o.keyPolicy.CanRead(srcBucket, srcKey) {
		writeS3Error(o.w, o.r, o.reqID, "AccessDenied", "access denied by key policy", http.StatusForbidden)
		return
	}
	directive := strings.ToUpper(strings.TrimSpace(o.r.Header.Get("x-amz-metadata-directive")))
	if directive == "" {
		directive = "COPY"
	}
	if directive != "COPY" && directive != "REPLACE" {
		writeS3Error(o.w, o.r, o.reqID, "InvalidArgument", "x-amz-metadata-directive must be COPY or REPLACE", http.StatusBadRequest)
		return
	}
	res, err := s.Svc.Copy(o.r.Context(), srcBucket, srcKey, o.bucket, o.key)
	if err != nil {
		s.fail(o, err)
		return
	}
	meta := store.ObjectMeta{Bucket: o.bucket, Key: o.key, ETag: res.ETag}
	if directive == "COPY" {
		if src, err := s.Svc.ObjectMeta(o.r.Context(), srcBucket, srcKey); err == nil {
			if src.ETag != "" {
				meta.ETag = src.ETag
				res.ETag = src.ETag
			}
			meta.ContentType = src.ContentType
			meta.StorageClass = src.StorageClass
			meta.Metadata = src.Metadata
			meta.Checksum = src.Checksum
		}
	}
	if directive == "REPLACE" {
		meta.ContentType = o.r.Header.Get("Content-Type")
		meta.StorageClass = strings.ToUpper(strings.TrimSpace(o.r.Header.Get("x-amz-storage-class")))
		meta.Metadata = userMetadataJSON(o.r)
	}
	if err := s.Svc.SetObjectMeta(o.r.Context(), meta); err != nil {
		s.fail(o, fmt.Errorf("store object metadata: %w", err))
		return
	}
	o.acctID = res.AccountID
	writeXML(o.w, http.StatusOK, copyObjectResult{
		LastModified: xmlTime(res.Modified),
		ETag:         quoteETag(res.ETag),
	})
}

func (s *Server) deleteObjects(o *opCtx) {
	body, err := io.ReadAll(io.LimitReader(o.r.Body, 4<<20))
	if err != nil {
		s.fail(o, err)
		return
	}
	if v := o.r.Header.Get("Content-MD5"); v != "" {
		raw, derr := base64.StdEncoding.DecodeString(v)
		sum := md5.Sum(body) // #nosec G401 -- S3 DeleteObjects requires Content-MD5
		if derr != nil || len(raw) != 16 || !bytes.Equal(raw, sum[:]) {
			writeS3Error(o.w, o.r, o.reqID, "BadDigest", "the Content-MD5 you specified did not match what we received", http.StatusBadRequest)
			return
		}
	}
	var req deleteObjectsRequest
	if err := xml.Unmarshal(body, &req); err != nil {
		writeS3Error(o.w, o.r, o.reqID, "MalformedXML", "the XML you provided was not well-formed", http.StatusBadRequest)
		return
	}
	if len(req.Objects) > 1000 {
		writeS3Error(o.w, o.r, o.reqID, "InvalidRequest", "at most 1000 keys can be deleted per request", http.StatusBadRequest)
		return
	}
	out := deleteResult{Xmlns: xmlNS}
	for _, item := range req.Objects {
		if o.keyPolicy != nil && !o.keyPolicy.CanWrite(o.bucket, item.Key) {
			out.Errors = append(out.Errors, deleteErrItem{Key: item.Key, Code: "AccessDenied", Message: "access denied by key policy"})
			continue
		}
		if err := s.Svc.Delete(o.r.Context(), o.bucket, item.Key); err != nil && !drive.IsNotFound(err) {
			out.Errors = append(out.Errors, deleteErrItem{Key: item.Key, Code: drive.CodeOf(err), Message: err.Error()})
			continue
		}
		if !req.Quiet {
			out.Deleted = append(out.Deleted, deletedItem{Key: item.Key})
		}
	}
	writeXML(o.w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// Subresources

func (s *Server) bucketSubresource(o *opCtx) bool {
	if !hasAnyQuery(o.r, "location", "versioning", "acl", "policy", "cors", "lifecycle", "encryption",
		"tagging", "object-lock", "replication", "website", "notification", "requestPayment",
		"logging", "accelerate", "publicAccessBlock", "ownershipControls", "intelligent-tiering", "inventory") {
		return false
	}
	if _, err := s.Svc.Bucket(o.r.Context(), o.bucket); err != nil {
		s.fail(o, err)
		return true
	}
	if hasQuery(o.r, "location") {
		writeXML(o.w, http.StatusOK, locationConstraint{Xmlns: xmlNS, Value: o.cfg.Region})
		return true
	}
	for _, sub := range bucketSubresources {
		if hasQuery(o.r, sub.query) {
			sub.serve(o)
			return true
		}
	}
	acceptSubresourceWrite(o)
	return true
}

// subresourceReply answers one bucket subresource query. bucketSubresources
// is ordered: the first query present in the request wins.
type subresourceReply struct {
	query string
	serve func(o *opCtx)
}

var bucketSubresources = []subresourceReply{
	{"versioning", rawXMLReply(`<VersioningConfiguration xmlns="` + xmlNS + `"/>`)},
	{"acl", rawXMLReply(`<AccessControlPolicy xmlns="` + xmlNS + `"><Owner><ID>s3drive</ID><DisplayName>s3drive</DisplayName></Owner><AccessControlList><Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID>s3drive</ID><DisplayName>s3drive</DisplayName></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>`)},
	{"policy", bucketPolicyReply},
	{"cors", rawXMLReply(`<CORSConfiguration xmlns="` + xmlNS + `"/>`)},
	{"lifecycle", rawXMLReply(`<LifecycleConfiguration xmlns="` + xmlNS + `"/>`)},
	{"encryption", notFoundReply("ServerSideEncryptionConfigurationNotFoundError", "The server side encryption configuration was not found")},
	{"tagging", rawXMLReply(`<Tagging xmlns="` + xmlNS + `"><TagSet></TagSet></Tagging>`)},
	{"object-lock", notFoundReply("ObjectLockConfigurationNotFoundError", "Object Lock configuration does not exist for this bucket")},
	{"replication", notFoundReply("ReplicationConfigurationNotFoundError", "The replication configuration was not found")},
	{"website", notFoundReply("NoSuchWebsiteConfiguration", "The specified bucket does not have a website configuration")},
	{"notification", rawXMLReply(`<NotificationConfiguration xmlns="` + xmlNS + `"/>`)},
	{"requestPayment", rawXMLReply(`<RequestPaymentConfiguration xmlns="` + xmlNS + `"><Payer>BucketOwner</Payer></RequestPaymentConfiguration>`)},
	{"logging", rawXMLReply(`<BucketLoggingStatus xmlns="` + xmlNS + `"/>`)},
	{"accelerate", rawXMLReply(`<AccelerateConfiguration xmlns="` + xmlNS + `"/>`)},
	{"publicAccessBlock", rawXMLReply(`<PublicAccessBlockConfiguration xmlns="` + xmlNS + `"/>`)},
	{"ownershipControls", rawXMLReply(`<OwnershipControls xmlns="` + xmlNS + `"/>`)},
}

func rawXMLReply(body string) func(*opCtx) {
	return func(o *opCtx) { writeRawXML(o.w, http.StatusOK, body) }
}

func notFoundReply(code, message string) func(*opCtx) {
	return func(o *opCtx) { writeS3Error(o.w, o.r, o.reqID, code, message, http.StatusNotFound) }
}

func bucketPolicyReply(o *opCtx) {
	switch o.r.Method {
	case http.MethodPut, http.MethodDelete:
		o.w.WriteHeader(http.StatusNoContent)
	default:
		writeS3Error(o.w, o.r, o.reqID, "NoSuchBucketPolicy", "The bucket policy does not exist", http.StatusNotFound)
	}
}

// acceptSubresourceWrite acknowledges writes to unsupported subresources
// (intelligent-tiering, inventory) and rejects reads.
func acceptSubresourceWrite(o *opCtx) {
	switch o.r.Method {
	case http.MethodPut, http.MethodPost:
		o.w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		o.w.WriteHeader(http.StatusNoContent)
	default:
		writeS3Error(o.w, o.r, o.reqID, "NotImplemented", "this bucket subresource is not supported", http.StatusNotImplemented)
	}
}

func (s *Server) objectSubresource(o *opCtx) bool {
	if !hasAnyQuery(o.r, "acl", "tagging", "retention", "legal-hold", "torrent", "attributes") {
		return false
	}
	switch {
	case hasQuery(o.r, "acl"):
		if o.r.Method == http.MethodPut {
			o.w.WriteHeader(http.StatusOK)
			return true
		}
		writeRawXML(o.w, http.StatusOK, `<AccessControlPolicy xmlns="`+xmlNS+`"><Owner><ID>s3drive</ID><DisplayName>s3drive</DisplayName></Owner><AccessControlList><Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID>s3drive</ID><DisplayName>s3drive</DisplayName></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>`)
	case hasQuery(o.r, "tagging"):
		switch o.r.Method {
		case http.MethodPut:
			o.w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			o.w.WriteHeader(http.StatusNoContent)
		default:
			writeRawXML(o.w, http.StatusOK, `<Tagging xmlns="`+xmlNS+`"><TagSet></TagSet></Tagging>`)
		}
	case hasQuery(o.r, "retention"), hasQuery(o.r, "legal-hold"):
		writeS3Error(o.w, o.r, o.reqID, "NoSuchObjectLockConfiguration", "object lock is not supported", http.StatusNotFound)
	case hasQuery(o.r, "torrent"):
		writeS3Error(o.w, o.r, o.reqID, "NotImplemented", "BitTorrent is not supported", http.StatusNotImplemented)
	case hasQuery(o.r, "attributes"):
		writeS3Error(o.w, o.r, o.reqID, "NotImplemented", "GetObjectAttributes is not supported", http.StatusNotImplemented)
	}
	return true
}

// ---------------------------------------------------------------------------
// Helpers

func (s *Server) methodNotAllowed(o *opCtx) {
	writeS3Error(o.w, o.r, o.reqID, "MethodNotAllowed", "the specified method is not allowed against this resource", http.StatusMethodNotAllowed)
}

func (s *Server) fail(o *opCtx, err error) {
	code, message, status := mapError(err)
	if status >= 500 {
		s.Log.Error("s3 operation failed", "op", o.op, "bucket", o.bucket, "key", o.key, "err", err)
	}
	writeS3Error(o.w, o.r, o.reqID, code, message, status)
}

func mapGoogleError(ae *google.APIError) (code, message string, status int) {
	switch ae.Status {
	case http.StatusUnauthorized:
		return "AccessDenied", "the connected Google account must be reauthorized", http.StatusForbidden
	case http.StatusNotFound:
		return "NoSuchKey", "the specified key does not exist", http.StatusNotFound
	case http.StatusForbidden:
		return "AccessDenied", ae.Message, http.StatusForbidden
	case http.StatusRequestedRangeNotSatisfiable:
		return "InvalidRange", "The requested range is not satisfiable", http.StatusRequestedRangeNotSatisfiable
	case http.StatusTooManyRequests:
		return "SlowDown", "Google Drive is rate limiting requests, please retry", http.StatusServiceUnavailable
	default:
		return "InternalError", "Google Drive request failed", http.StatusInternalServerError
	}
}

func mapError(err error) (code, message string, status int) {
	if errors.Is(err, errPayloadHashMismatch) {
		return "XAmzContentSHA256Mismatch", errPayloadHashMismatch.Error(), http.StatusBadRequest
	}
	if de, ok := errors.AsType[*drive.Error](err); ok {
		return de.Code, de.Message, de.Status
	}
	if ae, ok := errors.AsType[*google.APIError](err); ok {
		return mapGoogleError(ae)
	}
	if errors.Is(err, google.ErrReauth) {
		return "AccessDenied", "the connected Google account must be reauthorized", http.StatusForbidden
	}
	if errors.Is(err, store.ErrNotFound) {
		return "NoSuchKey", "the specified key does not exist", http.StatusNotFound
	}
	return "InternalError", "We encountered an internal error. Please try again.", http.StatusInternalServerError
}

func splitPath(r *http.Request) (bucket, key string) {
	path := strings.TrimPrefix(r.URL.EscapedPath(), "/")
	if path == "" {
		return "", ""
	}
	bucket, key, ok := strings.Cut(path, "/")
	if b, err := url.PathUnescape(bucket); err == nil {
		bucket = b
	}
	if !ok {
		return bucket, ""
	}
	if k, err := url.PathUnescape(key); err == nil {
		key = k
	}
	return bucket, key
}

func splitFirst(s string) (string, string) {
	return splitPathFromString(s)
}

func splitPathFromString(p string) (string, string) {
	p = strings.TrimPrefix(p, "/")
	a, b, _ := strings.Cut(p, "/")
	return a, b
}

func hasQuery(r *http.Request, name string) bool {
	_, ok := r.URL.Query()[name]
	return ok
}

func hasAnyQuery(r *http.Request, names ...string) bool {
	q := r.URL.Query()
	for _, n := range names {
		if _, ok := q[n]; ok {
			return true
		}
	}
	return false
}

func contentMD5(r *http.Request) (string, *AuthError) {
	v := r.Header.Get("Content-MD5")
	if v == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(raw) != 16 {
		return "", authErr("InvalidDigest", "the Content-MD5 you specified is not valid")
	}
	return hex.EncodeToString(raw), nil
}

func acctIDOf(a *store.Account) string {
	if a == nil {
		return ""
	}
	return a.ID
}

func opName(r *http.Request, bucket, key string) string {
	switch {
	case bucket == "":
		return "ListBuckets"
	case key == "":
		return bucketOpName(r)
	}
	return objectOpName(r)
}

func bucketOpName(r *http.Request) string {
	switch r.Method {
	case http.MethodPut:
		return "CreateBucket"
	case http.MethodDelete:
		return "DeleteBucket"
	case http.MethodHead:
		return "HeadBucket"
	case http.MethodPost:
		if hasQuery(r, "delete") {
			return "DeleteObjects"
		}
		return "Post"
	case http.MethodGet:
		switch {
		case hasQuery(r, "location"):
			return "GetBucketLocation"
		case hasQuery(r, "uploads"):
			return "ListMultipartUploads"
		}
		return "ListObjects"
	}
	return ""
}

// objectOpName names an object request; a request carrying uploadId belongs
// to the multipart variant of the method's operation.
func objectOpName(r *http.Request) string {
	multipart := r.URL.Query().Get("uploadId") != ""
	switch r.Method {
	case http.MethodPut:
		return putOpName(r, multipart)
	case http.MethodPost:
		return postOpName(r, multipart)
	case http.MethodGet:
		return pick(multipart, "ListParts", "GetObject")
	case http.MethodHead:
		return "HeadObject"
	case http.MethodDelete:
		return pick(multipart, "AbortMultipartUpload", "DeleteObject")
	}
	return ""
}

func putOpName(r *http.Request, multipart bool) string {
	if r.Header.Get("x-amz-copy-source") != "" {
		return "CopyObject"
	}
	return pick(multipart, "UploadPart", "PutObject")
}

func postOpName(r *http.Request, multipart bool) string {
	if hasQuery(r, "uploads") {
		return "CreateMultipartUpload"
	}
	return pick(multipart, "CompleteMultipartUpload", "PostObject")
}

func pick(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}

func (s *Server) applyCORS(w http.ResponseWriter, r *http.Request, cfg drive.Settings) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return
	}
	allowed := strings.TrimSpace(cfg.CORSOrigins)
	if allowed == "" || allowed == "*" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	} else {
		for candidate := range strings.SplitSeq(allowed, ",") {
			if strings.TrimSpace(candidate) == origin {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Add("Vary", "Origin")
				break
			}
		}
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, PUT, POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Expose-Headers", "ETag, Content-Length, Content-Range, Content-Type, Last-Modified, x-amz-request-id")
	w.Header().Set("Access-Control-Max-Age", "3600")
	if h := r.Header.Get("Access-Control-Request-Headers"); h != "" {
		w.Header().Set("Access-Control-Allow-Headers", h)
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if code > 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

func writeRawXML(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, xml.Header+body)
}
