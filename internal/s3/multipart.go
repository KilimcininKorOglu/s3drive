package s3

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"s3drive/internal/drive"
	"s3drive/internal/store"
)

// S3 caps a single multipart part at 5 GiB. The process-wide object limit may
// be lower, so use the smaller of the two.
func (s *Server) maxPartBytes() int64 {
	const s3PartMax = int64(5 << 30)
	if s.Svc.MaxObjectBytes > 0 && s.Svc.MaxObjectBytes < s3PartMax {
		return s.Svc.MaxObjectBytes
	}
	return s3PartMax
}

func (s *Server) createMultipartUpload(o *opCtx) {
	if err := drive.ValidateKey(o.key); err != nil {
		s.fail(o, err)
		return
	}
	if strings.HasSuffix(o.key, "/") {
		writeS3Error(o.w, o.r, o.reqID, "InvalidArgument", "multipart uploads require an object key that does not end with '/'", http.StatusBadRequest)
		return
	}
	ref, err := s.Svc.Bucket(o.r.Context(), o.bucket)
	if err != nil {
		s.fail(o, err)
		return
	}
	accountID := ""
	if ref.Account != nil {
		accountID = ref.Account.ID
	}
	id := store.NewID()
	contentType := o.r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	storageClass := strings.ToUpper(strings.TrimSpace(o.r.Header.Get("x-amz-storage-class")))
	if storageClass == "" {
		storageClass = "STANDARD"
	}
	if err := s.Store.CreateUpload(o.r.Context(), &store.Upload{
		ID: id, Bucket: o.bucket, Key: o.key, AccountID: accountID, ContentType: contentType,
		Metadata: userMetadataJSON(o.r), StorageClass: storageClass,
	}); err != nil {
		s.fail(o, err)
		return
	}
	writeXML(o.w, http.StatusOK, initiateMultipartResult{
		Xmlns: xmlNS, Bucket: o.bucket, Key: o.key, UploadID: id,
	})
}

func (s *Server) uploadPart(o *opCtx) {
	q := o.r.URL.Query()
	partNumber, err := strconv.Atoi(q.Get("partNumber"))
	if err != nil || partNumber < 1 || partNumber > 10000 {
		writeS3Error(o.w, o.r, o.reqID, "InvalidArgument", "partNumber must be between 1 and 10000", http.StatusBadRequest)
		return
	}
	uploadID := q.Get("uploadId")
	if _, err := s.Store.GetUpload(o.r.Context(), uploadID, o.bucket, o.key); err != nil {
		s.noSuchUpload(o)
		return
	}
	if o.r.Header.Get("x-amz-copy-source") != "" {
		s.uploadPartCopy(o, uploadID, partNumber)
		return
	}
	partLimit := s.maxPartBytes()
	if o.r.ContentLength > partLimit {
		writeS3Error(o.w, o.r, o.reqID, "EntityTooLarge", "part exceeds the maximum part size", http.StatusRequestEntityTooLarge)
		return
	}
	if err := s.Svc.CheckSpool(); err != nil {
		s.fail(o, err)
		return
	}
	dir := s.uploadDir(uploadID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		s.fail(o, err)
		return
	}
	if o.r.ContentLength > 0 {
		if total, err := stagedUploadBytes(dir, strconv.Itoa(partNumber)); err == nil &&
			s.Svc.MaxObjectBytes > 0 && total+o.r.ContentLength > s.Svc.MaxObjectBytes {
			writeS3Error(o.w, o.r, o.reqID, "EntityTooLarge", "object exceeds the configured size limit", http.StatusRequestEntityTooLarge)
			return
		}
	}
	path := filepath.Join(dir, strconv.Itoa(partNumber))
	tmp, err := os.CreateTemp(dir, "part-*")
	if err != nil {
		s.fail(o, err)
		return
	}
	h := md5.New()
	src := io.LimitReader(o.r.Body, partLimit+1)
	n, copyErr := io.Copy(io.MultiWriter(tmp, h), src)
	closeErr := tmp.Close()
	if copyErr == nil && n > partLimit {
		os.Remove(tmp.Name())
		writeS3Error(o.w, o.r, o.reqID, "EntityTooLarge", "part exceeds the maximum part size", http.StatusRequestEntityTooLarge)
		return
	}
	if copyErr != nil {
		os.Remove(tmp.Name())
		s.fail(o, copyErr)
		return
	}
	if closeErr != nil {
		os.Remove(tmp.Name())
		s.fail(o, closeErr)
		return
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if v := o.r.Header.Get("Content-MD5"); v != "" {
		raw, err := base64.StdEncoding.DecodeString(v)
		if err != nil || len(raw) != 16 || hex.EncodeToString(raw) != sum {
			os.Remove(tmp.Name())
			writeS3Error(o.w, o.r, o.reqID, "BadDigest", "the Content-MD5 you specified did not match what we received", http.StatusBadRequest)
			return
		}
	}
	if total, err := stagedUploadBytes(dir, strconv.Itoa(partNumber)); err == nil &&
		s.Svc.MaxObjectBytes > 0 && total+n > s.Svc.MaxObjectBytes {
		os.Remove(tmp.Name())
		writeS3Error(o.w, o.r, o.reqID, "EntityTooLarge", "object exceeds the configured size limit", http.StatusRequestEntityTooLarge)
		return
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		s.fail(o, err)
		return
	}
	_ = s.Store.TouchUpload(o.r.Context(), uploadID)
	o.bytes = n
	o.w.Header().Set("ETag", quoteETag(sum))
	o.w.WriteHeader(http.StatusOK)
}

// uploadPartCopy implements UploadPartCopy by downloading the requested
// source range and staging it exactly like an uploaded part.
func (s *Server) uploadPartCopy(o *opCtx, uploadID string, partNumber int) {
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
	if err := s.Svc.CheckSpool(); err != nil {
		s.fail(o, err)
		return
	}
	partLimit := s.maxPartBytes()
	rangeHeader := strings.TrimSpace(o.r.Header.Get("x-amz-copy-source-range"))
	src, err := s.Svc.Get(o.r.Context(), srcBucket, srcKey, rangeHeader)
	if err != nil {
		s.fail(o, err)
		return
	}
	defer src.Body.Close()

	dir := s.uploadDir(uploadID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		s.fail(o, err)
		return
	}
	tmp, err := os.CreateTemp(dir, "copy-*")
	if err != nil {
		s.fail(o, err)
		return
	}
	h := md5.New()
	n, copyErr := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(src.Body, partLimit+1))
	closeErr := tmp.Close()
	if copyErr == nil && n > partLimit {
		os.Remove(tmp.Name())
		writeS3Error(o.w, o.r, o.reqID, "EntityTooLarge", "part exceeds the maximum part size", http.StatusRequestEntityTooLarge)
		return
	}
	if copyErr != nil || closeErr != nil {
		os.Remove(tmp.Name())
		if copyErr != nil {
			s.fail(o, copyErr)
		} else {
			s.fail(o, closeErr)
		}
		return
	}
	sum := hex.EncodeToString(h.Sum(nil))
	path := filepath.Join(dir, strconv.Itoa(partNumber))
	if total, err := stagedUploadBytes(dir, strconv.Itoa(partNumber)); err == nil &&
		s.Svc.MaxObjectBytes > 0 && total+n > s.Svc.MaxObjectBytes {
		os.Remove(tmp.Name())
		writeS3Error(o.w, o.r, o.reqID, "EntityTooLarge", "object exceeds the configured size limit", http.StatusRequestEntityTooLarge)
		return
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		s.fail(o, err)
		return
	}
	_ = s.Store.TouchUpload(o.r.Context(), uploadID)
	o.bytes = n
	writeXML(o.w, http.StatusOK, copyPartResult{
		LastModified: xmlTime(time.Now()),
		ETag:         quoteETag(sum),
	})
}

func (s *Server) completeMultipartUpload(o *opCtx) {
	uploadID := o.r.URL.Query().Get("uploadId")
	upload, err := s.Store.GetUpload(o.r.Context(), uploadID, o.bucket, o.key)
	if err != nil {
		s.noSuchUpload(o)
		return
	}
	_ = s.Store.TouchUpload(o.r.Context(), uploadID)
	var req completeMultipartRequest
	if err := xml.NewDecoder(io.LimitReader(o.r.Body, 8<<20)).Decode(&req); err != nil {
		writeS3Error(o.w, o.r, o.reqID, "MalformedXML", "the XML you provided was not well-formed", http.StatusBadRequest)
		return
	}
	if len(req.Parts) == 0 {
		writeS3Error(o.w, o.r, o.reqID, "InvalidRequest", "you must specify at least one part", http.StatusBadRequest)
		return
	}
	sort.Slice(req.Parts, func(i, j int) bool { return req.Parts[i].PartNumber < req.Parts[j].PartNumber })

	dir := s.uploadDir(uploadID)
	tmp, err := os.CreateTemp(s.SpoolDir, "complete-*")
	if err != nil {
		s.fail(o, err)
		return
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	fullHash := md5.New()
	partHashes := make([]byte, 0, len(req.Parts)*md5.Size)
	seen := map[int]bool{}
	var total int64
	for _, part := range req.Parts {
		if part.PartNumber < 1 || seen[part.PartNumber] {
			tmp.Close()
			writeS3Error(o.w, o.r, o.reqID, "InvalidPart", "part numbers must be unique and positive", http.StatusBadRequest)
			return
		}
		seen[part.PartNumber] = true
		path := filepath.Join(dir, strconv.Itoa(part.PartNumber))
		f, err := os.Open(path)
		if err != nil {
			tmp.Close()
			writeS3Error(o.w, o.r, o.reqID, "InvalidPart", fmt.Sprintf("part %d was not uploaded", part.PartNumber), http.StatusBadRequest)
			return
		}
		partHash := md5.New()
		n, err := io.Copy(io.MultiWriter(tmp, fullHash, partHash), f)
		f.Close()
		if err != nil {
			tmp.Close()
			s.fail(o, err)
			return
		}
		expected := strings.Trim(part.ETag, `"`)
		actual := hex.EncodeToString(partHash.Sum(nil))
		if expected != "" && !strings.EqualFold(expected, actual) {
			tmp.Close()
			writeS3Error(o.w, o.r, o.reqID, "InvalidPart", fmt.Sprintf("part %d ETag does not match", part.PartNumber), http.StatusBadRequest)
			return
		}
		partHashes = append(partHashes, partHash.Sum(nil)...)
		total += n
	}
	if err := tmp.Close(); err != nil {
		s.fail(o, err)
		return
	}

	if s.Svc.MaxObjectBytes > 0 && total > s.Svc.MaxObjectBytes {
		writeS3Error(o.w, o.r, o.reqID, "EntityTooLarge", "object exceeds the configured size limit", http.StatusRequestEntityTooLarge)
		return
	}
	combined := md5.Sum(partHashes)
	multipartETag := hex.EncodeToString(combined[:]) + "-" + strconv.Itoa(len(req.Parts))
	res, err := s.Svc.PutFile(o.r.Context(), o.bucket, o.key, upload.ContentType, tmpPath, total, hex.EncodeToString(fullHash.Sum(nil)))
	if err != nil {
		s.fail(o, err)
		return
	}
	_ = s.Svc.SetObjectMeta(o.r.Context(), store.ObjectMeta{
		Bucket: o.bucket, Key: o.key, ETag: multipartETag,
		ContentType: upload.ContentType, StorageClass: upload.StorageClass,
		Metadata: upload.Metadata, Checksum: upload.Checksum,
	})
	_ = s.Store.DeleteUpload(o.r.Context(), uploadID)
	_ = os.RemoveAll(dir)

	o.acctID, o.bytes = res.AccountID, total
	o.w.Header().Set("ETag", quoteETag(multipartETag))
	writeXML(o.w, http.StatusOK, completeMultipartResult{
		Xmlns: xmlNS, Location: "/" + o.bucket + "/" + o.key,
		Bucket: o.bucket, Key: o.key, ETag: quoteETag(multipartETag),
	})
}

func (s *Server) abortMultipartUpload(o *opCtx) {
	uploadID := o.r.URL.Query().Get("uploadId")
	if _, err := s.Store.GetUpload(o.r.Context(), uploadID, o.bucket, o.key); err != nil {
		s.noSuchUpload(o)
		return
	}
	_ = s.Store.DeleteUpload(o.r.Context(), uploadID)
	_ = os.RemoveAll(s.uploadDir(uploadID))
	o.w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listParts(o *opCtx) {
	uploadID := o.r.URL.Query().Get("uploadId")
	upload, err := s.Store.GetUpload(o.r.Context(), uploadID, o.bucket, o.key)
	if err != nil {
		s.noSuchUpload(o)
		return
	}
	dir := s.uploadDir(uploadID)
	entries, _ := os.ReadDir(dir)
	type part struct {
		n    int
		size int64
		mod  time.Time
	}
	var parts []part
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		parts = append(parts, part{n: n, size: info.Size(), mod: info.ModTime()})
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].n < parts[j].n })
	maxParts := 1000
	if v := o.r.URL.Query().Get("max-parts"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeS3Error(o.w, o.r, o.reqID, "InvalidArgument", "invalid max-parts", http.StatusBadRequest)
			return
		}
		maxParts = n
	}
	marker := 0
	if v := o.r.URL.Query().Get("part-number-marker"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeS3Error(o.w, o.r, o.reqID, "InvalidArgument", "invalid part-number-marker", http.StatusBadRequest)
			return
		}
		marker = n
	}
	storageClass := upload.StorageClass
	if storageClass == "" {
		storageClass = "STANDARD"
	}
	out := listPartsResult{
		Xmlns: xmlNS, Bucket: o.bucket, Key: o.key, UploadID: upload.ID,
		Initiator:        owner{ID: "s3drive", DisplayName: "s3drive"},
		Owner:            owner{ID: "s3drive", DisplayName: "s3drive"},
		StorageClass:     storageClass,
		PartNumberMarker: marker,
		MaxParts:         maxParts,
	}
	for _, p := range parts {
		if p.n <= marker {
			continue
		}
		if maxParts == 0 || len(out.Parts) >= maxParts {
			out.IsTruncated = true
			break
		}
		path := filepath.Join(dir, strconv.Itoa(p.n))
		sum, _ := fileMD5(path)
		out.Parts = append(out.Parts, partEntry{
			PartNumber: p.n, LastModified: xmlTime(p.mod), ETag: quoteETag(sum), Size: p.size,
		})
		out.NextPartNumberMarker = p.n
	}
	writeXML(o.w, http.StatusOK, out)
}

func (s *Server) listMultipartUploads(o *opCtx) {
	q := o.r.URL.Query()
	uploads, err := s.Store.ListUploads(o.r.Context(), o.bucket)
	if err != nil {
		s.fail(o, err)
		return
	}
	maxUploads := 1000
	if v := q.Get("max-uploads"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeS3Error(o.w, o.r, o.reqID, "InvalidArgument", "invalid max-uploads", http.StatusBadRequest)
			return
		}
		maxUploads = n
	}
	prefix := q.Get("prefix")
	delimiter := q.Get("delimiter")
	keyMarker := q.Get("key-marker")
	uploadMarker := q.Get("upload-id-marker")
	encoding := q.Get("encoding-type")
	if encoding != "" && encoding != "url" {
		writeS3Error(o.w, o.r, o.reqID, "InvalidArgument", "invalid encoding-type", http.StatusBadRequest)
		return
	}
	sort.Slice(uploads, func(i, j int) bool {
		if uploads[i].Key == uploads[j].Key {
			return uploads[i].ID < uploads[j].ID
		}
		return uploads[i].Key < uploads[j].Key
	})
	out := listMultipartUploadsResult{
		Xmlns: xmlNS, Bucket: o.bucket, MaxUploads: maxUploads,
		Prefix: encodeKey(prefix, encoding), Delimiter: encodeKey(delimiter, encoding),
		KeyMarker: encodeKey(keyMarker, encoding), UploadIDMarker: uploadMarker,
		EncodingType: encoding,
	}
	seenPrefix := map[string]bool{}
	for _, u := range uploads {
		if prefix != "" && !strings.HasPrefix(u.Key, prefix) {
			continue
		}
		if keyMarker != "" {
			if u.Key < keyMarker || (u.Key == keyMarker && (uploadMarker == "" || u.ID <= uploadMarker)) {
				continue
			}
		}
		if delimiter != "" {
			rest := strings.TrimPrefix(u.Key, prefix)
			if i := strings.Index(rest, delimiter); i >= 0 {
				cp := prefix + rest[:i+len(delimiter)]
				// A marker inside a common-prefix group means that group was
				// already returned on an earlier page.
				if cp <= keyMarker {
					continue
				}
				if !seenPrefix[cp] {
					seenPrefix[cp] = true
					out.CommonPrefixes = append(out.CommonPrefixes, commonPrefix{Prefix: cp})
				}
				continue
			}
		}
		if maxUploads == 0 || len(out.Uploads) >= maxUploads {
			out.IsTruncated = true
			break
		}
		storageClass := u.StorageClass
		if storageClass == "" {
			storageClass = "STANDARD"
		}
		out.Uploads = append(out.Uploads, multipartEntry{
			Key: u.Key, UploadID: u.ID,
			Initiator:    owner{ID: "s3drive", DisplayName: "s3drive"},
			Owner:        owner{ID: "s3drive", DisplayName: "s3drive"},
			StorageClass: storageClass, Initiated: xmlTime(u.CreatedAt),
		})
		out.NextKeyMarker = u.Key
		out.NextUploadIDMarker = u.ID
	}
	if encoding == "url" {
		for i := range out.Uploads {
			out.Uploads[i].Key = encodeKey(out.Uploads[i].Key, encoding)
		}
		for i := range out.CommonPrefixes {
			out.CommonPrefixes[i].Prefix = encodeKey(out.CommonPrefixes[i].Prefix, encoding)
		}
		if out.NextKeyMarker != "" {
			out.NextKeyMarker = encodeKey(out.NextKeyMarker, encoding)
		}
	}
	writeXML(o.w, http.StatusOK, out)
}

func (s *Server) noSuchUpload(o *opCtx) {
	writeS3Error(o.w, o.r, o.reqID, "NoSuchUpload", "the specified multipart upload does not exist", http.StatusNotFound)
}

func (s *Server) uploadDir(uploadID string) string {
	return filepath.Join(s.SpoolDir, "multipart", safeUploadID(uploadID))
}

// stagedUploadBytes totals committed part files, excluding a part that is
// about to be replaced. Temporary files do not match the numeric naming
// convention and are intentionally ignored.
func stagedUploadBytes(dir, skip string) (int64, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var total int64
	for _, e := range entries {
		if e.IsDir() || e.Name() == skip {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		total += info.Size()
	}
	return total, nil
}

func fileMD5(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
