package s3

import (
	"cmp"
	"crypto/md5" // #nosec G501 -- S3 ETag checksum, not a security primitive
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"net/http"
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
	dir, ok := s.preparePartUpload(o, uploadID, partNumber)
	if !ok {
		return
	}
	staged, ok := s.stagePart(o, dir, "part-*", o.r.Body)
	if !ok {
		return
	}
	if !contentMD5Matches(o.r.Header.Get("Content-MD5"), staged.sum) {
		s.removeTemp(staged.path)
		writeS3Error(o.w, o.r, o.reqID, "BadDigest", "the Content-MD5 you specified did not match what we received", http.StatusBadRequest)
		return
	}
	if !s.commitPart(o, uploadID, dir, partNumber, staged) {
		return
	}
	o.w.Header().Set("ETag", quoteETag(staged.sum))
	o.w.WriteHeader(http.StatusOK)
}

// preparePartUpload checks the declared part size, spool space and the
// object limit before any byte is read. It writes the error response itself.
func (s *Server) preparePartUpload(o *opCtx, uploadID string, partNumber int) (string, bool) {
	if o.r.ContentLength > s.maxPartBytes() {
		writeS3Error(o.w, o.r, o.reqID, "EntityTooLarge", "part exceeds the maximum part size", http.StatusRequestEntityTooLarge)
		return "", false
	}
	if err := s.Svc.CheckSpool(); err != nil {
		s.fail(o, err)
		return "", false
	}
	dir := s.uploadDir(uploadID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		s.fail(o, err)
		return "", false
	}
	if o.r.ContentLength > 0 && s.stagedLimitExceeded(o, dir, partNumber, o.r.ContentLength) {
		return "", false
	}
	return dir, true
}

// stagedFile is a part written to a temp file in the upload directory.
type stagedFile struct {
	path string
	sum  string // hex MD5
	size int64
}

// stagePart copies at most maxPartBytes from src into a new temp file and
// hashes it. On failure it removes the file and writes the error response.
func (s *Server) stagePart(o *opCtx, dir, pattern string, src io.Reader) (stagedFile, bool) {
	partLimit := s.maxPartBytes()
	tmp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		s.fail(o, err)
		return stagedFile{}, false
	}
	h := md5.New() // #nosec G401 -- S3 part/multipart ETag checksum
	n, copyErr := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(src, partLimit+1))
	closeErr := tmp.Close()
	switch {
	case copyErr == nil && n > partLimit:
		s.removeTemp(tmp.Name())
		writeS3Error(o.w, o.r, o.reqID, "EntityTooLarge", "part exceeds the maximum part size", http.StatusRequestEntityTooLarge)
		return stagedFile{}, false
	case copyErr != nil || closeErr != nil:
		s.removeTemp(tmp.Name())
		s.fail(o, cmp.Or(copyErr, closeErr))
		return stagedFile{}, false
	}
	return stagedFile{path: tmp.Name(), sum: hex.EncodeToString(h.Sum(nil)), size: n}, true
}

// contentMD5Matches reports whether an optional Content-MD5 header (base64)
// equals the hex MD5 of the received bytes.
func contentMD5Matches(header, sumHex string) bool {
	if header == "" {
		return true
	}
	raw, err := base64.StdEncoding.DecodeString(header)
	return err == nil && len(raw) == 16 && hex.EncodeToString(raw) == sumHex
}

// commitPart re-checks the object limit with the real size and moves the
// staged file into place as the part. It writes the error response itself.
func (s *Server) commitPart(o *opCtx, uploadID, dir string, partNumber int, staged stagedFile) bool {
	if s.stagedLimitExceeded(o, dir, partNumber, staged.size) {
		s.removeTemp(staged.path)
		return false
	}
	if err := os.Rename(staged.path, filepath.Join(dir, strconv.Itoa(partNumber))); err != nil {
		s.removeTemp(staged.path)
		s.fail(o, err)
		return false
	}
	s.touchUpload(o, uploadID)
	o.bytes = staged.size
	return true
}

// uploadPartCopy implements UploadPartCopy by downloading the requested
// source range and staging it exactly like an uploaded part.
func (s *Server) uploadPartCopy(o *opCtx, uploadID string, partNumber int) {
	srcBucket, srcKey, ok := copySource(o)
	if !ok {
		return
	}
	if err := s.Svc.CheckSpool(); err != nil {
		s.fail(o, err)
		return
	}
	rangeHeader := strings.TrimSpace(o.r.Header.Get("x-amz-copy-source-range"))
	src, err := s.Svc.Get(o.r.Context(), srcBucket, srcKey, rangeHeader)
	if err != nil {
		s.fail(o, err)
		return
	}
	defer func() { _ = src.Body.Close() }() // read side of the copy source

	dir := s.uploadDir(uploadID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		s.fail(o, err)
		return
	}
	staged, ok := s.stagePart(o, dir, "copy-*", src.Body)
	if !ok || !s.commitPart(o, uploadID, dir, partNumber, staged) {
		return
	}
	writeXML(o.w, http.StatusOK, copyPartResult{
		LastModified: xmlTime(time.Now()),
		ETag:         quoteETag(staged.sum),
	})
}

// readCompleteRequest decodes the CompleteMultipartUpload body and returns
// its parts sorted by number. It writes the error response itself.
func readCompleteRequest(o *opCtx) ([]completePart, bool) {
	var req completeMultipartRequest
	if err := xml.NewDecoder(io.LimitReader(o.r.Body, 8<<20)).Decode(&req); err != nil {
		writeS3Error(o.w, o.r, o.reqID, "MalformedXML", "the XML you provided was not well-formed", http.StatusBadRequest)
		return nil, false
	}
	if len(req.Parts) == 0 {
		writeS3Error(o.w, o.r, o.reqID, "InvalidRequest", "you must specify at least one part", http.StatusBadRequest)
		return nil, false
	}
	sort.Slice(req.Parts, func(i, j int) bool { return req.Parts[i].PartNumber < req.Parts[j].PartNumber })
	return req.Parts, true
}

// assembly accumulates the combined object and its multipart ETag inputs.
type assembly struct {
	full       hash.Hash
	partHashes []byte
	total      int64
}

// assembleParts appends every listed part to dst in order, checking for
// duplicates, missing parts and ETag mismatches. It writes the error
// response itself.
func (s *Server) assembleParts(o *opCtx, dir string, parts []completePart, dst io.Writer, a *assembly) bool {
	seen := map[int]bool{}
	for _, part := range parts {
		if part.PartNumber < 1 || seen[part.PartNumber] {
			writeS3Error(o.w, o.r, o.reqID, "InvalidPart", "part numbers must be unique and positive", http.StatusBadRequest)
			return false
		}
		seen[part.PartNumber] = true
		if !s.appendPart(o, dir, part, dst, a) {
			return false
		}
	}
	return true
}

func (s *Server) appendPart(o *opCtx, dir string, part completePart, dst io.Writer, a *assembly) bool {
	path := filepath.Join(dir, strconv.Itoa(part.PartNumber))
	f, err := os.Open(path) // #nosec G304 -- spool path: safeUploadID keeps [a-z0-9], part number is an int
	if err != nil {
		writeS3Error(o.w, o.r, o.reqID, "InvalidPart", fmt.Sprintf("part %d was not uploaded", part.PartNumber), http.StatusBadRequest)
		return false
	}
	partHash := md5.New() // #nosec G401 -- S3 part/multipart ETag checksum
	n, err := io.Copy(io.MultiWriter(dst, a.full, partHash), f)
	_ = f.Close() // read-only part file; io.Copy reported read errors
	if err != nil {
		s.fail(o, err)
		return false
	}
	expected := strings.Trim(part.ETag, `"`)
	if expected != "" && !strings.EqualFold(expected, hex.EncodeToString(partHash.Sum(nil))) {
		writeS3Error(o.w, o.r, o.reqID, "InvalidPart", fmt.Sprintf("part %d ETag does not match", part.PartNumber), http.StatusBadRequest)
		return false
	}
	a.partHashes = append(a.partHashes, partHash.Sum(nil)...)
	a.total += n
	return true
}

func (s *Server) completeMultipartUpload(o *opCtx) {
	uploadID := o.r.URL.Query().Get("uploadId")
	upload, err := s.Store.GetUpload(o.r.Context(), uploadID, o.bucket, o.key)
	if err != nil {
		s.noSuchUpload(o)
		return
	}
	s.touchUpload(o, uploadID)
	parts, ok := readCompleteRequest(o)
	if !ok {
		return
	}
	dir := s.uploadDir(uploadID)
	tmp, err := os.CreateTemp(s.SpoolDir, "complete-*")
	if err != nil {
		s.fail(o, err)
		return
	}
	tmpPath := tmp.Name()
	defer s.removeTemp(tmpPath)

	a := &assembly{full: md5.New(), partHashes: make([]byte, 0, len(parts)*md5.Size)} // #nosec G401 -- S3 ETag checksum
	if !s.assembleParts(o, dir, parts, tmp, a) {
		_ = tmp.Close() // error path: the temp file is removed by the deferred removeTemp
		return
	}
	if err := tmp.Close(); err != nil {
		s.fail(o, err)
		return
	}
	if s.Svc.MaxObjectBytes > 0 && a.total > s.Svc.MaxObjectBytes {
		writeS3Error(o.w, o.r, o.reqID, "EntityTooLarge", "object exceeds the configured size limit", http.StatusRequestEntityTooLarge)
		return
	}
	total := a.total
	combined := md5.Sum(a.partHashes) // #nosec G401 -- S3 multipart ETag format
	multipartETag := hex.EncodeToString(combined[:]) + "-" + strconv.Itoa(len(parts))
	res, err := s.Svc.PutFile(o.r.Context(), o.bucket, o.key, upload.ContentType, tmpPath, total, hex.EncodeToString(a.full.Sum(nil)))
	if err != nil {
		s.fail(o, err)
		return
	}
	if err := s.Svc.SetObjectMeta(o.r.Context(), store.ObjectMeta{
		Bucket: o.bucket, Key: o.key, ETag: multipartETag,
		ContentType: upload.ContentType, StorageClass: upload.StorageClass,
		Metadata: upload.Metadata, Checksum: upload.Checksum,
	}); err != nil {
		s.fail(o, fmt.Errorf("store object metadata: %w", err))
		return
	}
	s.finishUpload(o, uploadID, dir)

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
	if err := s.Store.DeleteUpload(o.r.Context(), uploadID); err != nil {
		s.fail(o, fmt.Errorf("delete upload: %w", err))
		return
	}
	if err := os.RemoveAll(s.uploadDir(uploadID)); err != nil {
		s.Log.Warn("remove aborted upload parts", "upload", uploadID, "err", err)
	}
	o.w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listParts(o *opCtx) {
	uploadID := o.r.URL.Query().Get("uploadId")
	upload, err := s.Store.GetUpload(o.r.Context(), uploadID, o.bucket, o.key)
	if err != nil {
		s.noSuchUpload(o)
		return
	}
	q := o.r.URL.Query()
	maxParts, ok := queryCount(q.Get("max-parts"), 1000)
	if !ok {
		writeS3Error(o.w, o.r, o.reqID, "InvalidArgument", "invalid max-parts", http.StatusBadRequest)
		return
	}
	marker, ok := queryCount(q.Get("part-number-marker"), 0)
	if !ok {
		writeS3Error(o.w, o.r, o.reqID, "InvalidArgument", "invalid part-number-marker", http.StatusBadRequest)
		return
	}
	dir := s.uploadDir(uploadID)
	parts, err := stagedParts(dir)
	if err != nil {
		s.fail(o, fmt.Errorf("list staged parts: %w", err))
		return
	}
	out := listPartsResult{
		Xmlns: xmlNS, Bucket: o.bucket, Key: o.key, UploadID: upload.ID,
		Initiator:        owner{ID: "s3drive", DisplayName: "s3drive"},
		Owner:            owner{ID: "s3drive", DisplayName: "s3drive"},
		StorageClass:     cmp.Or(upload.StorageClass, "STANDARD"),
		PartNumberMarker: marker,
		MaxParts:         maxParts,
	}
	if err := fillPartsPage(&out, dir, parts); err != nil {
		s.fail(o, err)
		return
	}
	writeXML(o.w, http.StatusOK, out)
}

// queryCount parses a non-negative count query value; empty means def.
func queryCount(v string, def int) (int, bool) {
	if v == "" {
		return def, true
	}
	n, err := strconv.Atoi(v)
	return n, err == nil && n >= 0
}

type stagedPart struct {
	n    int
	size int64
	mod  time.Time
}

// stagedParts lists the committed part files of an upload by part number.
// A missing directory means no part was uploaded yet.
func stagedParts(dir string) ([]stagedPart, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var parts []stagedPart
	for _, e := range entries {
		n, err := strconv.Atoi(e.Name())
		if e.IsDir() || err != nil {
			continue // temp files and other entries are not parts
		}
		info, err := e.Info()
		if errors.Is(err, fs.ErrNotExist) {
			continue // replaced or removed meanwhile
		}
		if err != nil {
			return nil, err
		}
		parts = append(parts, stagedPart{n: n, size: info.Size(), mod: info.ModTime()})
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].n < parts[j].n })
	return parts, nil
}

// fillPartsPage adds the parts after PartNumberMarker, up to MaxParts.
func fillPartsPage(out *listPartsResult, dir string, parts []stagedPart) error {
	for _, p := range parts {
		if p.n <= out.PartNumberMarker {
			continue
		}
		if out.MaxParts == 0 || len(out.Parts) >= out.MaxParts {
			out.IsTruncated = true
			return nil
		}
		sum, err := fileMD5(filepath.Join(dir, strconv.Itoa(p.n)))
		if err != nil {
			return fmt.Errorf("hash part %d: %w", p.n, err)
		}
		out.Parts = append(out.Parts, partEntry{
			PartNumber: p.n, LastModified: xmlTime(p.mod), ETag: quoteETag(sum), Size: p.size,
		})
		out.NextPartNumberMarker = p.n
	}
	return nil
}

func (s *Server) listMultipartUploads(o *opCtx) {
	q := o.r.URL.Query()
	uploads, err := s.Store.ListUploads(o.r.Context(), o.bucket)
	if err != nil {
		s.fail(o, err)
		return
	}
	maxUploads, ok := queryCount(q.Get("max-uploads"), 1000)
	if !ok {
		writeS3Error(o.w, o.r, o.reqID, "InvalidArgument", "invalid max-uploads", http.StatusBadRequest)
		return
	}
	encoding := q.Get("encoding-type")
	if encoding != "" && encoding != "url" {
		writeS3Error(o.w, o.r, o.reqID, "InvalidArgument", "invalid encoding-type", http.StatusBadRequest)
		return
	}
	page := uploadPage{
		prefix: q.Get("prefix"), delimiter: q.Get("delimiter"),
		keyMarker: q.Get("key-marker"), uploadMarker: q.Get("upload-id-marker"), max: maxUploads,
	}
	sort.Slice(uploads, func(i, j int) bool {
		if uploads[i].Key == uploads[j].Key {
			return uploads[i].ID < uploads[j].ID
		}
		return uploads[i].Key < uploads[j].Key
	})
	out := listMultipartUploadsResult{
		Xmlns: xmlNS, Bucket: o.bucket, MaxUploads: maxUploads,
		Prefix: encodeKey(page.prefix, encoding), Delimiter: encodeKey(page.delimiter, encoding),
		KeyMarker: encodeKey(page.keyMarker, encoding), UploadIDMarker: page.uploadMarker,
		EncodingType: encoding,
	}
	page.fill(&out, uploads)
	if encoding == "url" {
		encodeUploadListing(&out)
	}
	writeXML(o.w, http.StatusOK, out)
}

// uploadPage is one ListMultipartUploads page request.
type uploadPage struct {
	prefix, delimiter, keyMarker, uploadMarker string
	max                                        int
}

// fill adds uploads (sorted by key, then ID) after the markers, grouping
// keys that contain the delimiter into common prefixes.
func (p uploadPage) fill(out *listMultipartUploadsResult, uploads []*store.Upload) {
	seenPrefix := map[string]bool{}
	for _, u := range uploads {
		if !p.includes(u) {
			continue
		}
		if cp, grouped := p.group(u.Key); grouped {
			// A marker inside a common-prefix group means that group was
			// already returned on an earlier page.
			if cp > p.keyMarker && !seenPrefix[cp] {
				seenPrefix[cp] = true
				out.CommonPrefixes = append(out.CommonPrefixes, commonPrefix{Prefix: cp})
			}
			continue
		}
		if p.max == 0 || len(out.Uploads) >= p.max {
			out.IsTruncated = true
			return
		}
		out.Uploads = append(out.Uploads, multipartEntry{
			Key: u.Key, UploadID: u.ID,
			Initiator:    owner{ID: "s3drive", DisplayName: "s3drive"},
			Owner:        owner{ID: "s3drive", DisplayName: "s3drive"},
			StorageClass: cmp.Or(u.StorageClass, "STANDARD"), Initiated: xmlTime(u.CreatedAt),
		})
		out.NextKeyMarker = u.Key
		out.NextUploadIDMarker = u.ID
	}
}

// includes applies the prefix filter and skips uploads at or before the
// key-marker/upload-id-marker position.
func (p uploadPage) includes(u *store.Upload) bool {
	if p.prefix != "" && !strings.HasPrefix(u.Key, p.prefix) {
		return false
	}
	if p.keyMarker == "" {
		return true
	}
	if u.Key != p.keyMarker {
		return u.Key > p.keyMarker
	}
	return p.uploadMarker != "" && u.ID > p.uploadMarker
}

// group returns the common prefix a key rolls up into under the delimiter.
func (p uploadPage) group(key string) (string, bool) {
	if p.delimiter == "" {
		return "", false
	}
	rest := strings.TrimPrefix(key, p.prefix)
	i := strings.Index(rest, p.delimiter)
	if i < 0 {
		return "", false
	}
	return p.prefix + rest[:i+len(p.delimiter)], true
}

func encodeUploadListing(out *listMultipartUploadsResult) {
	for i := range out.Uploads {
		out.Uploads[i].Key = encodeKey(out.Uploads[i].Key, "url")
	}
	for i := range out.CommonPrefixes {
		out.CommonPrefixes[i].Prefix = encodeKey(out.CommonPrefixes[i].Prefix, "url")
	}
	if out.NextKeyMarker != "" {
		out.NextKeyMarker = encodeKey(out.NextKeyMarker, "url")
	}
}

func (s *Server) noSuchUpload(o *opCtx) {
	writeS3Error(o.w, o.r, o.reqID, "NoSuchUpload", "the specified multipart upload does not exist", http.StatusNotFound)
}

// touchUpload refreshes the upload's activity time. A failure only risks an
// early stale-upload cleanup, so it is logged and the request continues.
func (s *Server) touchUpload(o *opCtx, uploadID string) {
	if err := s.Store.TouchUpload(o.r.Context(), uploadID); err != nil {
		s.Log.Warn("touch multipart upload", "upload", uploadID, "err", err)
	}
}

// finishUpload drops the upload record and its staged parts after the object
// was stored. The object is already complete, so failures are logged.
func (s *Server) finishUpload(o *opCtx, uploadID, dir string) {
	if err := s.Store.DeleteUpload(o.r.Context(), uploadID); err != nil {
		s.Log.Warn("delete completed upload", "upload", uploadID, "err", err)
	}
	if err := os.RemoveAll(dir); err != nil {
		s.Log.Warn("remove completed upload parts", "upload", uploadID, "err", err)
	}
}

// removeTemp deletes a spool temp file. A failure leaves data on disk, so it
// is logged rather than dropped.
func (s *Server) removeTemp(path string) {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.Log.Warn("remove multipart temp file", "path", path, "err", err)
	}
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
		if errors.Is(err, fs.ErrNotExist) {
			continue // the part was replaced or removed meanwhile
		}
		if err != nil {
			return 0, err
		}
		total += info.Size()
	}
	return total, nil
}

// stagedLimitExceeded reports whether adding incoming bytes to the parts
// already staged in dir would pass the object size limit. It writes the error
// response itself; a failure to measure the staged parts rejects the request
// rather than skipping the limit.
func (s *Server) stagedLimitExceeded(o *opCtx, dir string, partNumber int, incoming int64) bool {
	if s.Svc.MaxObjectBytes <= 0 {
		return false
	}
	total, err := stagedUploadBytes(dir, strconv.Itoa(partNumber))
	if err != nil {
		s.fail(o, fmt.Errorf("measure staged parts: %w", err))
		return true
	}
	if total+incoming > s.Svc.MaxObjectBytes {
		writeS3Error(o.w, o.r, o.reqID, "EntityTooLarge", "object exceeds the configured size limit", http.StatusRequestEntityTooLarge)
		return true
	}
	return false
}

func fileMD5(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- callers pass a part file under uploadDir (sanitized upload ID)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }() // read-only part file
	h := md5.New()                   // #nosec G401 -- S3 part/multipart ETag checksum
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
