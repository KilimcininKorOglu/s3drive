package s3

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
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

func (s *Server) createMultipartUpload(o *opCtx) {
	if err := drive.ValidateKey(o.key); err != nil {
		s.fail(o, err)
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
	if err := s.Store.CreateUpload(o.r.Context(), &store.Upload{
		ID: id, Bucket: o.bucket, Key: o.key, AccountID: accountID, ContentType: contentType,
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
	dir := s.uploadDir(uploadID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		s.fail(o, err)
		return
	}
	path := filepath.Join(dir, strconv.Itoa(partNumber))
	tmp, err := os.CreateTemp(dir, "part-*")
	if err != nil {
		s.fail(o, err)
		return
	}
	h := md5.New()
	n, copyErr := io.Copy(io.MultiWriter(tmp, h), o.r.Body)
	closeErr := tmp.Close()
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
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		s.fail(o, err)
		return
	}
	o.bytes = n
	o.w.Header().Set("ETag", quoteETag(sum))
	o.w.WriteHeader(http.StatusOK)
}

func (s *Server) completeMultipartUpload(o *opCtx) {
	uploadID := o.r.URL.Query().Get("uploadId")
	upload, err := s.Store.GetUpload(o.r.Context(), uploadID, o.bucket, o.key)
	if err != nil {
		s.noSuchUpload(o)
		return
	}
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

	combined := md5.Sum(partHashes)
	multipartETag := hex.EncodeToString(combined[:]) + "-" + strconv.Itoa(len(req.Parts))
	res, err := s.Svc.PutFile(o.r.Context(), o.bucket, o.key, upload.ContentType, tmpPath, total, hex.EncodeToString(fullHash.Sum(nil)))
	if err != nil {
		s.fail(o, err)
		return
	}
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
	out := listPartsResult{
		Xmlns: xmlNS, Bucket: o.bucket, Key: o.key, UploadID: upload.ID,
		Initiator:    owner{ID: "s3drive", DisplayName: "s3drive"},
		Owner:        owner{ID: "s3drive", DisplayName: "s3drive"},
		StorageClass: "STANDARD", MaxParts: 1000,
	}
	for _, p := range parts {
		path := filepath.Join(dir, strconv.Itoa(p.n))
		sum, _ := fileMD5(path)
		out.Parts = append(out.Parts, partEntry{
			PartNumber: p.n, LastModified: xmlTime(p.mod), ETag: quoteETag(sum), Size: p.size,
		})
	}
	writeXML(o.w, http.StatusOK, out)
}

func (s *Server) listMultipartUploads(o *opCtx) {
	uploads, err := s.Store.ListUploads(o.r.Context(), o.bucket)
	if err != nil {
		s.fail(o, err)
		return
	}
	out := listMultipartUploadsResult{
		Xmlns: xmlNS, Bucket: o.bucket, MaxUploads: 1000,
	}
	for _, u := range uploads {
		out.Uploads = append(out.Uploads, multipartEntry{
			Key: u.Key, UploadID: u.ID,
			Initiator:    owner{ID: "s3drive", DisplayName: "s3drive"},
			Owner:        owner{ID: "s3drive", DisplayName: "s3drive"},
			StorageClass: "STANDARD", Initiated: xmlTime(u.CreatedAt),
		})
	}
	writeXML(o.w, http.StatusOK, out)
}

func (s *Server) noSuchUpload(o *opCtx) {
	writeS3Error(o.w, o.r, o.reqID, "NoSuchUpload", "the specified multipart upload does not exist", http.StatusNotFound)
}

func (s *Server) uploadDir(uploadID string) string {
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, uploadID)
	return filepath.Join(s.SpoolDir, "multipart", safe)
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
