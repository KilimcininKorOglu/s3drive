// Package s3 exposes the S3-compatible HTTP API.
package s3

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
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
		r.Body = newPayloadReader(r.Body, auth)
		defer r.Body.Close()
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

type opCtx struct {
	w       *statusWriter
	r       *http.Request
	reqID   string
	cfg     drive.Settings
	bucket  string
	key     string
	op      string
	acctID  string
	bytes   int64
	started time.Time
}

func (o *opCtx) record(s *Server) {
	status := o.w.status
	if o.op == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.Store.AddEvent(ctx, store.Event{
		Op: o.op, Bucket: o.bucket, Key: o.key, AccountID: o.acctID,
		Bytes: o.bytes, Status: status, MS: time.Since(o.started).Milliseconds(),
	})
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
		s.createBucket(o)
	case http.MethodDelete:
		s.deleteBucket(o)
	case http.MethodGet:
		if s.bucketSubresource(o) {
			return
		}
		if o.r.URL.Query().Get("uploads") != "" || hasQuery(o.r, "uploads") {
			s.listMultipartUploads(o)
			return
		}
		s.listObjects(o)
	case http.MethodPost:
		if hasQuery(o.r, "delete") {
			s.deleteObjects(o)
			return
		}
		s.methodNotAllowed(o)
	default:
		s.methodNotAllowed(o)
	}
}

func (s *Server) objectRequest(o *opCtx) {
	q := o.r.URL.Query()
	if hasQuery(o.r, "uploads") && o.r.Method == http.MethodPost {
		s.createMultipartUpload(o)
		return
	}
	if q.Get("uploadId") != "" {
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
		return
	}
	if s.objectSubresource(o) {
		return
	}
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
	prefix := q.Get("prefix")
	delimiter := q.Get("delimiter")
	encoding := q.Get("encoding-type")
	if encoding != "" && encoding != "url" {
		writeS3Error(o.w, o.r, o.reqID, "InvalidArgument", "invalid encoding-type", http.StatusBadRequest)
		return
	}
	maxKeys := 1000
	if v := q.Get("max-keys"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeS3Error(o.w, o.r, o.reqID, "InvalidArgument", "invalid max-keys", http.StatusBadRequest)
			return
		}
		if n > 0 {
			maxKeys = n
		}
	}
	v2 := q.Get("list-type") == "2"
	var after string
	if v2 {
		if tok := q.Get("continuation-token"); tok != "" {
			raw, err := base64.RawURLEncoding.DecodeString(tok)
			if err != nil {
				writeS3Error(o.w, o.r, o.reqID, "InvalidArgument", "invalid continuation token", http.StatusBadRequest)
				return
			}
			after = string(raw)
		} else {
			after = q.Get("start-after")
		}
	} else {
		after = q.Get("marker")
	}

	res, err := s.Svc.List(o.r.Context(), o.bucket, prefix, delimiter, maxKeys, after)
	if err != nil {
		s.fail(o, err)
		return
	}
	ref, _ := s.Svc.Bucket(o.r.Context(), o.bucket)
	if ref != nil && ref.Account != nil {
		o.acctID = ref.Account.ID
	}

	out := listBucketResult{
		Xmlns:        xmlNS,
		Name:         o.bucket,
		Prefix:       encodeKey(prefix, encoding),
		Delimiter:    encodeKey(delimiter, encoding),
		MaxKeys:      maxKeys,
		IsTruncated:  res.IsTruncated,
		EncodingType: encoding,
	}
	for _, obj := range res.Objects {
		out.Contents = append(out.Contents, listObject{
			Key:          encodeKey(obj.Key, encoding),
			LastModified: xmlTime(obj.Modified),
			ETag:         quoteETag(obj.ETag),
			Size:         obj.Size,
			StorageClass: "STANDARD",
		})
	}
	for _, p := range res.CommonPrefixes {
		out.CommonPrefixes = append(out.CommonPrefixes, commonPrefix{Prefix: encodeKey(p, encoding)})
	}
	if v2 {
		out.KeyCount = len(res.Objects) + len(res.CommonPrefixes)
		out.ContinuationToken = q.Get("continuation-token")
		out.StartAfter = q.Get("start-after")
		if res.IsTruncated {
			out.NextContinuationToken = base64.RawURLEncoding.EncodeToString([]byte(res.NextAfter))
		}
	} else {
		out.Marker = after
		if res.IsTruncated {
			out.NextMarker = encodeKey(res.NextAfter, encoding)
		}
	}
	writeXML(o.w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// Object operations

func (s *Server) putObject(o *opCtx) {
	if strings.HasSuffix(o.key, "/") {
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
		return
	}
	expected, aerr := contentMD5(o.r)
	if aerr != nil {
		writeS3Error(o.w, o.r, o.reqID, aerr.Code, aerr.Message, aerr.Status)
		return
	}
	contentType := o.r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	res, err := s.Svc.PutVerified(o.r.Context(), o.bucket, o.key, contentType, o.r.Body, expected)
	if err != nil {
		s.fail(o, err)
		return
	}
	o.acctID, o.bytes = res.AccountID, res.Size
	o.w.Header().Set("ETag", quoteETag(res.ETag))
	o.w.WriteHeader(http.StatusOK)
}

func (s *Server) getObject(o *opCtx) {
	rangeHeader := o.r.Header.Get("Range")
	obj, err := s.Svc.Get(o.r.Context(), o.bucket, o.key, rangeHeader)
	if err != nil {
		s.fail(o, err)
		return
	}
	defer obj.Body.Close()
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
	if v := o.r.URL.Query().Get("response-content-type"); v != "" {
		o.w.Header().Set("Content-Type", v)
	}
	if v := o.r.URL.Query().Get("response-content-disposition"); v != "" {
		o.w.Header().Set("Content-Disposition", v)
	}
	if v := o.r.URL.Query().Get("response-cache-control"); v != "" {
		o.w.Header().Set("Cache-Control", v)
	}
	o.w.WriteHeader(status)
	n, _ := io.Copy(o.w, obj.Body)
	o.bytes = n
}

func (s *Server) headObject(o *opCtx) {
	obj, acct, err := s.Svc.Stat(o.r.Context(), o.bucket, o.key)
	if err != nil {
		s.fail(o, err)
		return
	}
	o.acctID = acctIDOf(acct)
	o.bytes = obj.Size
	if done := checkConditions(o, &drive.ObjectReader{Object: *obj}); done {
		return
	}
	setObjectHeaders(o, &drive.ObjectReader{Object: *obj})
	o.w.WriteHeader(http.StatusOK)
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
	for _, candidate := range strings.Split(header, ",") {
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
	res, err := s.Svc.Copy(o.r.Context(), srcBucket, srcKey, o.bucket, o.key)
	if err != nil {
		s.fail(o, err)
		return
	}
	o.acctID = res.AccountID
	writeXML(o.w, http.StatusOK, copyObjectResult{
		LastModified: xmlTime(res.Modified),
		ETag:         quoteETag(res.ETag),
	})
}

func (s *Server) deleteObjects(o *opCtx) {
	var req deleteObjectsRequest
	if err := xml.NewDecoder(io.LimitReader(o.r.Body, 4<<20)).Decode(&req); err != nil {
		writeS3Error(o.w, o.r, o.reqID, "MalformedXML", "the XML you provided was not well-formed", http.StatusBadRequest)
		return
	}
	if len(req.Objects) > 1000 {
		writeS3Error(o.w, o.r, o.reqID, "InvalidRequest", "at most 1000 keys can be deleted per request", http.StatusBadRequest)
		return
	}
	out := deleteResult{Xmlns: xmlNS}
	for _, item := range req.Objects {
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
	if hasQuery(o.r, "location") {
		writeXML(o.w, http.StatusOK, locationConstraint{Xmlns: xmlNS, Value: o.cfg.Region})
		return true
	}
	switch {
	case hasQuery(o.r, "versioning"):
		writeRawXML(o.w, http.StatusOK, `<VersioningConfiguration xmlns="`+xmlNS+`"/>`)
	case hasQuery(o.r, "acl"):
		writeRawXML(o.w, http.StatusOK, `<AccessControlPolicy xmlns="`+xmlNS+`"><Owner><ID>s3drive</ID><DisplayName>s3drive</DisplayName></Owner><AccessControlList><Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID>s3drive</ID><DisplayName>s3drive</DisplayName></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>`)
	case hasQuery(o.r, "policy"):
		writeS3Error(o.w, o.r, o.reqID, "NoSuchBucketPolicy", "The bucket policy does not exist", http.StatusNotFound)
	case hasQuery(o.r, "cors"):
		writeRawXML(o.w, http.StatusOK, `<CORSConfiguration xmlns="`+xmlNS+`"/>`)
	case hasQuery(o.r, "lifecycle"):
		writeRawXML(o.w, http.StatusOK, `<LifecycleConfiguration xmlns="`+xmlNS+`"/>`)
	case hasQuery(o.r, "encryption"):
		writeS3Error(o.w, o.r, o.reqID, "ServerSideEncryptionConfigurationNotFoundError", "The server side encryption configuration was not found", http.StatusNotFound)
	case hasQuery(o.r, "tagging"):
		writeRawXML(o.w, http.StatusOK, `<Tagging xmlns="`+xmlNS+`"><TagSet></TagSet></Tagging>`)
	case hasQuery(o.r, "object-lock"):
		writeS3Error(o.w, o.r, o.reqID, "ObjectLockConfigurationNotFoundError", "Object Lock configuration does not exist for this bucket", http.StatusNotFound)
	case hasQuery(o.r, "replication"):
		writeS3Error(o.w, o.r, o.reqID, "ReplicationConfigurationNotFoundError", "The replication configuration was not found", http.StatusNotFound)
	case hasQuery(o.r, "website"):
		writeS3Error(o.w, o.r, o.reqID, "NoSuchWebsiteConfiguration", "The specified bucket does not have a website configuration", http.StatusNotFound)
	case hasQuery(o.r, "notification"):
		writeRawXML(o.w, http.StatusOK, `<NotificationConfiguration xmlns="`+xmlNS+`"/>`)
	case hasQuery(o.r, "requestPayment"):
		writeRawXML(o.w, http.StatusOK, `<RequestPaymentConfiguration xmlns="`+xmlNS+`"><Payer>BucketOwner</Payer></RequestPaymentConfiguration>`)
	case hasQuery(o.r, "logging"):
		writeRawXML(o.w, http.StatusOK, `<BucketLoggingStatus xmlns="`+xmlNS+`"/>`)
	case hasQuery(o.r, "accelerate"):
		writeRawXML(o.w, http.StatusOK, `<AccelerateConfiguration xmlns="`+xmlNS+`"/>`)
	case hasQuery(o.r, "publicAccessBlock"):
		writeRawXML(o.w, http.StatusOK, `<PublicAccessBlockConfiguration xmlns="`+xmlNS+`"/>`)
	case hasQuery(o.r, "ownershipControls"):
		writeRawXML(o.w, http.StatusOK, `<OwnershipControls xmlns="`+xmlNS+`"/>`)
	default:
		switch o.r.Method {
		case http.MethodPut, http.MethodPost:
			o.w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			o.w.WriteHeader(http.StatusNoContent)
		default:
			writeS3Error(o.w, o.r, o.reqID, "NotImplemented", "this bucket subresource is not supported", http.StatusNotImplemented)
		}
	}
	return true
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

func mapError(err error) (code, message string, status int) {
	var de *drive.Error
	if errors.As(err, &de) {
		return de.Code, de.Message, de.Status
	}
	var ae *google.APIError
	if errors.As(err, &ae) {
		switch {
		case ae.Status == http.StatusUnauthorized:
			return "AccessDenied", "the connected Google account must be reauthorized", http.StatusForbidden
		case ae.Status == http.StatusNotFound:
			return "NoSuchKey", "the specified key does not exist", http.StatusNotFound
		case ae.Status == http.StatusForbidden:
			return "AccessDenied", ae.Message, http.StatusForbidden
		case ae.Status == http.StatusTooManyRequests:
			return "SlowDown", "Google Drive is rate limiting requests, please retry", http.StatusServiceUnavailable
		default:
			return "InternalError", "Google Drive request failed", http.StatusInternalServerError
		}
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
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		return "", ""
	}
	bucket, key, ok := strings.Cut(path, "/")
	if !ok {
		return bucket, ""
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
	if bucket == "" {
		return "ListBuckets"
	}
	if key == "" {
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
			default:
				return "ListObjects"
			}
		}
		return ""
	}
	q := r.URL.Query()
	switch r.Method {
	case http.MethodPut:
		if r.Header.Get("x-amz-copy-source") != "" {
			return "CopyObject"
		}
		if q.Get("uploadId") != "" {
			return "UploadPart"
		}
		return "PutObject"
	case http.MethodPost:
		if hasQuery(r, "uploads") {
			return "CreateMultipartUpload"
		}
		if q.Get("uploadId") != "" {
			return "CompleteMultipartUpload"
		}
		return "PostObject"
	case http.MethodGet:
		if q.Get("uploadId") != "" {
			return "ListParts"
		}
		return "GetObject"
	case http.MethodHead:
		return "HeadObject"
	case http.MethodDelete:
		if q.Get("uploadId") != "" {
			return "AbortMultipartUpload"
		}
		return "DeleteObject"
	}
	return ""
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
		for _, candidate := range strings.Split(allowed, ",") {
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
