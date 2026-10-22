package webui

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"s3drive/internal/config"
	"s3drive/internal/drive"
	"s3drive/internal/s3"
	"s3drive/internal/secure"
	"s3drive/internal/store"
)

type accountView struct {
	ID          string
	Name        string
	Email       string
	Picture     string
	Created     string
	Used        int64
	Limit       int64
	Pct         int
	Class       string
	Warn        bool
	QuotaErr    string
	NeedsReauth bool
	BucketCount int
}

type eventView struct {
	When       string
	Op         string
	Target     string
	Size       int64
	Status     int
	StatusKind string
	Kind       string
}

type dashboardData struct {
	baseData
	Accounts    []accountView
	BucketCount int
	Used        int64
	Limit       int64
	Stats       store.Stats
	Events      []eventView
	HasKeys     bool
	OAuthReady  bool
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	b := s.base(w, r, l.t("nav.dashboard"), l.t("dashboard.subtitle"), "dashboard", true)
	s.render(w, r, "dashboard", s.buildDashboard(r, b))
}

func (s *Server) dashboardPartial(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	b := s.base(w, r, l.t("nav.dashboard"), "", "dashboard", false)
	s.renderPartial(w, r, "dashboard_body", s.buildDashboard(r, b))
}

func (s *Server) buildDashboard(r *http.Request, b baseData) dashboardData {
	ctx := r.Context()
	l := s.t(r)
	accounts, _ := s.Store.ListAccounts(ctx)
	buckets, _ := s.Svc.ListBuckets(ctx)
	used, limit, _, _ := s.Svc.TotalStorage(ctx)
	stats, _ := s.Store.StatsSince(ctx, time.Now().Add(-24*time.Hour))
	events, _ := s.Store.RecentEvents(ctx, 14)
	hasKeys, _ := s.Store.HasActiveAccessKey(ctx)
	counts := s.bucketCounts(ctx)

	data := dashboardData{
		baseData: b, BucketCount: len(buckets), Used: used, Limit: limit,
		Stats: stats, HasKeys: hasKeys, OAuthReady: s.oauthReady(r),
	}
	for _, a := range accounts {
		v := accountView{
			ID: a.ID, Name: a.Name, Email: a.Email, Picture: a.Picture,
			Created: formatDate(a.CreatedAt, l.date), NeedsReauth: a.NeedsReauth,
			BucketCount: counts[a.ID],
		}
		if about, err := s.Svc.AccountQuota(ctx, a, false); err != nil {
			v.QuotaErr = err.Error()
			v.Class = "danger"
		} else {
			v.Used, v.Limit = about.Usage, about.Limit
			v.Pct, v.Class = quota(about.Usage, about.Limit)
			v.Warn = v.Class != ""
		}
		data.Accounts = append(data.Accounts, v)
	}
	for _, e := range events {
		kind := "ok"
		if e.Status >= 400 {
			kind = "warn"
		}
		if e.Status >= 500 {
			kind = "danger"
		}
		target := e.Key
		if target == "" {
			target = e.Bucket
		} else if e.Bucket != "" {
			target = e.Bucket + "/" + e.Key
		}
		if target == "" {
			target = "—"
		}
		data.Events = append(data.Events, eventView{
			When: s.shortWhen(l, e.TS), Op: e.Op, Target: target, Size: e.Bytes,
			Status: e.Status, StatusKind: kind, Kind: opKind(e.Op),
		})
	}
	return data
}

func (s *Server) shortWhen(l *lang, t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	now := time.Now()
	if t.Year() == now.Year() && t.YearDay() == now.YearDay() {
		return t.Local().Format("15:04")
	}
	return t.Local().Format(l.date)
}

func opKind(op string) string {
	if strings.HasPrefix(op, "Put") || strings.Contains(op, "Upload") || op == "CompleteMultipartUpload" || op == "CopyObject" {
		return "accent"
	}
	return ""
}

func quota(used, limit int64) (int, string) {
	if limit <= 0 {
		return 0, ""
	}
	pct := int(used * 100 / limit)
	if pct > 100 {
		pct = 100
	}
	class := ""
	if pct >= 90 {
		class = "danger"
	} else if pct >= 75 {
		class = "warn"
	}
	return pct, class
}

func (s *Server) bucketCounts(ctx context.Context) map[string]int {
	out := map[string]int{}
	buckets, err := s.Store.ListBuckets(ctx)
	if err != nil {
		return out
	}
	for _, b := range buckets {
		out[b.AccountID]++
	}
	return out
}

// ---------------------------------------------------------------------------
// Files

type crumbView struct {
	Name   string
	Prefix string
	Last   bool
}

type folderView struct {
	Name   string
	Prefix string
}

type fileView struct {
	Key         string
	Name        string
	When        string
	Size        int64
	AccountMail string
	Preview     string
	Native      bool
}

type filesData struct {
	baseData
	Buckets    []*drive.BucketRef
	Bucket     string
	Prefix     string
	Crumbs     []crumbView
	Folders    []folderView
	Files      []fileView
	ItemCount  int
	NextToken  string
	Pool       bool
	Notice     *flashMessage
	SearchTerm string
}

func (s *Server) files(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	b := s.base(w, r, l.t("nav.files"), l.t("files.subtitle"), "files", true)
	data := s.buildFiles(r, b, r.URL.Query().Get("bucket"), normalizePrefix(r.URL.Query().Get("prefix")), r.URL.Query().Get("after"), nil)
	if q := strings.TrimSpace(r.URL.Query().Get("q")); q != "" {
		data.SearchTerm = q
		data.Folders = nil
		data.Files = nil
		data.NextToken = ""
		objects, err := s.Svc.Search(r.Context(), data.Bucket, q, 200)
		if err != nil {
			data.Notice = &flashMessage{Kind: "error", Text: err.Error()}
		}
		for _, o := range objects {
			data.Files = append(data.Files, fileView{
				Key: o.Key, Name: filepath.Base(o.Key), When: s.shortWhen(l, o.Modified),
				Size: o.Size, AccountMail: o.AccountMail, Preview: previewKind(o.Key, o.ContentType),
			})
		}
		data.ItemCount = len(data.Files)
	}
	s.render(w, r, "files", data)
}

func previewKind(key, contentType string) string {
	ct := strings.ToLower(contentType)
	if strings.HasPrefix(ct, "image/") && !strings.Contains(ct, "svg") {
		return "image"
	}
	if ct == "application/pdf" || strings.HasSuffix(strings.ToLower(key), ".pdf") {
		return "pdf"
	}
	switch strings.ToLower(filepath.Ext(key)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif":
		return "image"
	case ".pdf":
		return "pdf"
	case ".txt", ".md", ".json", ".csv", ".log", ".xml", ".yaml", ".yml":
		return "text"
	}
	return ""
}

func normalizePrefix(prefix string) string {
	prefix = strings.TrimPrefix(prefix, "/")
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return prefix
}

func (s *Server) buildFiles(r *http.Request, b baseData, bucket, prefix, afterToken string, notice *flashMessage) filesData {
	ctx := r.Context()
	l := s.t(r)
	buckets, _ := s.Svc.ListBuckets(ctx)
	data := filesData{baseData: b, Buckets: buckets, Bucket: bucket, Prefix: prefix, Notice: notice}
	if bucket == "" && len(buckets) > 0 {
		bucket = buckets[0].Name
		data.Bucket = bucket
	}
	if bucket == "" {
		return data
	}
	for _, ref := range buckets {
		if ref.Name == bucket {
			data.Pool = ref.Pool
			break
		}
	}

	after := ""
	if afterToken != "" {
		if raw, err := base64.RawURLEncoding.DecodeString(afterToken); err == nil {
			after = string(raw)
		}
	}
	res, err := s.Svc.ListUI(ctx, bucket, prefix, "/", 1000, after)
	if err != nil {
		if data.Notice == nil {
			data.Notice = &flashMessage{Kind: "error", Text: err.Error()}
		}
	} else {
		for _, p := range res.CommonPrefixes {
			name := strings.TrimPrefix(p, prefix)
			name = strings.TrimSuffix(name, "/")
			if name == "" {
				continue
			}
			data.Folders = append(data.Folders, folderView{Name: name, Prefix: p})
		}
		for _, o := range res.Objects {
			name := strings.TrimPrefix(o.Key, prefix)
			if name == "" || strings.Contains(name, "/") {
				name = filepath.Base(o.Key)
			}
			preview := previewKind(o.Key, o.ContentType)
			native := drive.IsNativeDoc(o.ContentType)
			if native {
				preview = "pdf"
			}
			data.Files = append(data.Files, fileView{
				Key: o.Key, Name: name, When: s.shortWhen(l, o.Modified),
				Size: o.Size, AccountMail: o.AccountMail, Preview: preview, Native: native,
			})
		}
		if res.IsTruncated && res.NextAfter != "" {
			data.NextToken = base64.RawURLEncoding.EncodeToString([]byte(res.NextAfter))
		}
	}
	data.ItemCount = len(data.Folders) + len(data.Files)

	// Breadcrumbs: bucket root, then one crumb per prefix segment.
	data.Crumbs = append(data.Crumbs, crumbView{Name: bucket, Prefix: ""})
	if prefix != "" {
		parts := strings.Split(strings.TrimSuffix(prefix, "/"), "/")
		cumulative := ""
		for i, part := range parts {
			cumulative += part + "/"
			data.Crumbs = append(data.Crumbs, crumbView{Name: part, Prefix: cumulative, Last: i == len(parts)-1})
		}
	}
	if len(data.Crumbs) == 1 {
		data.Crumbs[0].Last = true
	}
	return data
}

func (s *Server) upload(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		s.filePartial(w, r, r.FormValue("bucket"), normalizePrefix(r.FormValue("prefix")), &flashMessage{Kind: "error", Text: err.Error()})
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	bucket := r.FormValue("bucket")
	prefix := normalizePrefix(r.FormValue("prefix"))
	headers := r.MultipartForm.File["files"]
	if bucket == "" {
		s.filePartial(w, r, bucket, prefix, &flashMessage{Kind: "error", Text: l.t("flash.no_bucket")})
		return
	}
	if len(headers) == 0 {
		s.filePartial(w, r, bucket, prefix, &flashMessage{Kind: "error", Text: l.t("flash.error", l.t("files.choose"))})
		return
	}
	ok, failed := 0, 0
	var firstErr error
	for _, fh := range headers {
		name := sanitizeName(fh.Filename)
		if name == "" {
			continue
		}
		key := prefix + name
		f, err := fh.Open()
		if err != nil {
			failed++
			firstErr = err
			continue
		}
		ct := fh.Header.Get("Content-Type")
		if ct == "" {
			ct = mime.TypeByExtension(filepath.Ext(name))
		}
		if ct == "" {
			ct = "application/octet-stream"
		}
		_, err = s.Svc.Put(r.Context(), bucket, key, ct, f)
		f.Close()
		if err != nil {
			failed++
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		ok++
	}
	var notice *flashMessage
	if failed > 0 {
		text := l.errorText(firstErr)
		if ok > 0 {
			text = l.t("flash.uploaded", ok) + " — " + text
		}
		notice = &flashMessage{Kind: "error", Text: text}
	} else {
		notice = &flashMessage{Kind: "ok", Text: l.t("flash.uploaded", ok)}
	}
	s.filePartial(w, r, bucket, prefix, notice)
}

func cleanRelPath(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	parts := strings.Split(name, "/")
	var out []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || part == "." || part == ".." {
			continue
		}
		part = sanitizeName(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return strings.Join(out, "/")
}

func (s *Server) uploadFolder(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		s.filePartial(w, r, r.FormValue("bucket"), normalizePrefix(r.FormValue("prefix")), &flashMessage{Kind: "error", Text: err.Error()})
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	bucket := r.FormValue("bucket")
	prefix := normalizePrefix(r.FormValue("prefix"))
	headers := r.MultipartForm.File["files"]
	rels := r.MultipartForm.Value["rel"]
	if bucket == "" || len(headers) == 0 {
		s.filePartial(w, r, bucket, prefix, &flashMessage{Kind: "error", Text: l.t("flash.no_selection")})
		return
	}
	ok, failed := 0, 0
	var firstErr error
	for i, fh := range headers {
		rel := fh.Filename
		if i < len(rels) && strings.TrimSpace(rels[i]) != "" {
			rel = rels[i]
		}
		rel = cleanRelPath(rel)
		if rel == "" {
			continue
		}
		f, err := fh.Open()
		if err != nil {
			failed++
			firstErr = err
			continue
		}
		ct := fh.Header.Get("Content-Type")
		if ct == "" {
			ct = mime.TypeByExtension(filepath.Ext(rel))
		}
		if ct == "" {
			ct = "application/octet-stream"
		}
		_, err = s.Svc.Put(r.Context(), bucket, prefix+rel, ct, f)
		f.Close()
		if err != nil {
			failed++
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		ok++
	}
	var notice *flashMessage
	if failed > 0 {
		notice = &flashMessage{Kind: "error", Text: l.errorText(firstErr)}
		if ok > 0 {
			notice.Text = l.t("flash.uploaded", ok) + " — " + notice.Text
		}
	} else {
		notice = &flashMessage{Kind: "ok", Text: l.t("flash.uploaded", ok)}
	}
	s.filePartial(w, r, bucket, prefix, notice)
}

const (
	uiMinPartSize = int64(8 << 20)
	uiMaxPartSize = int64(1 << 30)
	uiPartCount   = int64(10000)
)

func uploadSafeID(id string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, id)
}

func (s *Server) webUploadDir(id string) string {
	return filepath.Join(s.Cfg.SpoolDir, "multipart", uploadSafeID(id))
}

func (s *Server) uploadInit(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	name := sanitizeName(filepath.Base(strings.TrimSpace(r.FormValue("name"))))
	bucket := strings.TrimSpace(r.FormValue("bucket"))
	prefix := normalizePrefix(r.FormValue("prefix"))
	if name == "" || bucket == "" {
		http.Error(w, l.t("flash.invalid_name"), http.StatusBadRequest)
		return
	}
	key := prefix + name
	if err := drive.ValidateKey(key); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := s.Svc.Bucket(r.Context(), bucket); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	size, _ := strconv.ParseInt(r.FormValue("size"), 10, 64)
	if size < 0 {
		http.Error(w, "invalid object size", http.StatusBadRequest)
		return
	}
	if s.Svc.MaxObjectBytes > 0 && size > s.Svc.MaxObjectBytes {
		http.Error(w, "object exceeds the configured size limit", http.StatusRequestEntityTooLarge)
		return
	}
	// Keep the browser upload within 10,000 parts while staying efficient for
	// ordinary files. The client stores this value so a resumed upload keeps
	// using the same boundaries.
	partSize := uiMinPartSize
	if size > 0 {
		needed := (size + uiPartCount - 1) / uiPartCount
		if needed > partSize {
			partSize = needed
		}
	}
	if partSize > uiMaxPartSize {
		http.Error(w, "object is too large for a browser upload", http.StatusRequestEntityTooLarge)
		return
	}
	ct := strings.TrimSpace(r.FormValue("content_type"))
	if ct == "" {
		ct = mime.TypeByExtension(filepath.Ext(name))
	}
	if ct == "" {
		ct = "application/octet-stream"
	}
	id := store.NewID()
	if err := s.Store.CreateUpload(r.Context(), &store.Upload{
		ID: id, Bucket: bucket, Key: key, ContentType: ct, StorageClass: "STANDARD", Size: size,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "key": key, "part_size": partSize})
}

func (s *Server) uploadPart(w http.ResponseWriter, r *http.Request) {
	uploadID := r.URL.Query().Get("upload_id")
	part, err := strconv.Atoi(r.URL.Query().Get("part"))
	if err != nil || part < 1 || part > 10000 {
		http.Error(w, "invalid part number", http.StatusBadRequest)
		return
	}
	up, err := s.Store.GetUploadByID(r.Context(), uploadID)
	if err != nil {
		http.Error(w, "upload session not found", http.StatusNotFound)
		return
	}
	if r.ContentLength > uiMaxPartSize {
		http.Error(w, "part too large", http.StatusRequestEntityTooLarge)
		return
	}
	dir := s.webUploadDir(up.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmp, err := os.CreateTemp(dir, "part-*")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	body := http.MaxBytesReader(w, r.Body, uiMaxPartSize)
	n, copyErr := io.Copy(tmp, body)
	closeErr := tmp.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(tmp.Name())
		if copyErr != nil {
			http.Error(w, copyErr.Error(), http.StatusBadRequest)
		} else {
			http.Error(w, closeErr.Error(), http.StatusInternalServerError)
		}
		return
	}
	if total, err := stagedUploadBytes(dir, strconv.Itoa(part)); err != nil {
		_ = os.Remove(tmp.Name())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else if total+n > s.Svc.MaxObjectBytes && s.Svc.MaxObjectBytes > 0 {
		_ = os.Remove(tmp.Name())
		http.Error(w, "object exceeds the configured size limit", http.StatusRequestEntityTooLarge)
		return
	} else if up.Size > 0 && total+n > up.Size {
		_ = os.Remove(tmp.Name())
		http.Error(w, "upload exceeds the declared object size", http.StatusRequestEntityTooLarge)
		return
	}
	final := filepath.Join(dir, strconv.Itoa(part))
	_ = os.Remove(final)
	if err := os.Rename(tmp.Name(), final); err != nil {
		_ = os.Remove(tmp.Name())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.Store.TouchUpload(r.Context(), up.ID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) uploadComplete(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	uploadID := r.FormValue("upload_id")
	up, err := s.Store.GetUploadByID(r.Context(), uploadID)
	if err != nil {
		s.filePartialStatus(w, r, r.FormValue("bucket"), normalizePrefix(r.FormValue("prefix")), &flashMessage{Kind: "error", Text: l.t("flash.upload_missing")}, http.StatusNotFound)
		return
	}
	dir := s.webUploadDir(up.ID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		s.filePartialStatus(w, r, up.Bucket, normalizePrefix(r.FormValue("prefix")), &flashMessage{Kind: "error", Text: l.t("flash.upload_missing")}, http.StatusNotFound)
		return
	}
	type partFile struct {
		n    int
		path string
	}
	var parts []partFile
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		n, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		parts = append(parts, partFile{n: n, path: filepath.Join(dir, entry.Name())})
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].n < parts[j].n })
	if len(parts) == 0 {
		s.filePartialStatus(w, r, up.Bucket, normalizePrefix(r.FormValue("prefix")), &flashMessage{Kind: "error", Text: l.t("flash.upload_missing")}, http.StatusNotFound)
		return
	}
	for i, part := range parts {
		if part.n != i+1 {
			s.filePartialStatus(w, r, up.Bucket, normalizePrefix(r.FormValue("prefix")), &flashMessage{Kind: "error", Text: l.t("flash.upload_incomplete", i+1)}, http.StatusConflict)
			return
		}
	}
	// Combine staged parts into one file, opening them one at a time so a
	// large multipart upload cannot exhaust file descriptors.
	combined, err := os.CreateTemp(dir, "combined-*")
	if err != nil {
		s.filePartialStatus(w, r, up.Bucket, normalizePrefix(r.FormValue("prefix")), &flashMessage{Kind: "error", Text: err.Error()}, http.StatusInternalServerError)
		return
	}
	combinedPath := combined.Name()
	defer os.Remove(combinedPath)
	h := md5.New()
	var total int64
	for _, part := range parts {
		f, err := os.Open(part.path)
		if err != nil {
			combined.Close()
			s.filePartialStatus(w, r, up.Bucket, normalizePrefix(r.FormValue("prefix")), &flashMessage{Kind: "error", Text: err.Error()}, http.StatusInternalServerError)
			return
		}
		n, copyErr := io.Copy(io.MultiWriter(combined, h), f)
		f.Close()
		if copyErr != nil {
			combined.Close()
			s.filePartialStatus(w, r, up.Bucket, normalizePrefix(r.FormValue("prefix")), &flashMessage{Kind: "error", Text: copyErr.Error()}, http.StatusInternalServerError)
			return
		}
		total += n
	}
	if err := combined.Close(); err != nil {
		s.filePartialStatus(w, r, up.Bucket, normalizePrefix(r.FormValue("prefix")), &flashMessage{Kind: "error", Text: err.Error()}, http.StatusInternalServerError)
		return
	}
	if up.Size > 0 && total != up.Size {
		s.filePartialStatus(w, r, up.Bucket, normalizePrefix(r.FormValue("prefix")), &flashMessage{Kind: "error", Text: l.t("flash.upload_size")}, http.StatusConflict)
		return
	}
	if s.Svc.MaxObjectBytes > 0 && total > s.Svc.MaxObjectBytes {
		s.filePartialStatus(w, r, up.Bucket, normalizePrefix(r.FormValue("prefix")), &flashMessage{Kind: "error", Text: l.t("err.too_large")}, http.StatusRequestEntityTooLarge)
		return
	}
	_, putErr := s.Svc.PutFile(r.Context(), up.Bucket, up.Key, up.ContentType, combinedPath, total, hex.EncodeToString(h.Sum(nil)))
	if putErr != nil {
		// Keep the upload record and staged parts so a transient Drive error can
		// be retried by selecting the same file again.
		s.filePartialStatus(w, r, up.Bucket, normalizePrefix(r.FormValue("prefix")), &flashMessage{Kind: "error", Text: l.errorText(putErr)}, http.StatusBadGateway)
		return
	}
	_ = s.Store.DeleteUpload(r.Context(), up.ID)
	_ = os.RemoveAll(dir)
	s.filePartial(w, r, up.Bucket, normalizePrefix(r.FormValue("prefix")), &flashMessage{Kind: "ok", Text: l.t("flash.uploaded", 1)})
}

func stagedUploadBytes(dir, exclude string) (int64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || name == exclude || strings.HasPrefix(name, "part-") || strings.HasPrefix(name, "combined-") {
			continue
		}
		if _, err := strconv.Atoi(name); err != nil {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return 0, err
		}
		total += info.Size()
	}
	return total, nil
}

func (s *Server) uploadAbort(w http.ResponseWriter, r *http.Request) {
	uploadID := r.FormValue("upload_id")
	if uploadID != "" {
		_ = s.Store.DeleteUpload(r.Context(), uploadID)
		_ = os.RemoveAll(s.webUploadDir(uploadID))
	}
	w.WriteHeader(http.StatusNoContent)
}

func sanitizeName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	name = filepath.Base(name)
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		return ""
	}
	name = strings.Map(func(r rune) rune {
		if r == '/' || r == 0 || r < 32 {
			return -1
		}
		return r
	}, name)
	return name
}

func (s *Server) createFolder(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	bucket := r.FormValue("bucket")
	prefix := normalizePrefix(r.FormValue("prefix"))
	name := strings.Trim(strings.TrimSpace(r.FormValue("name")), "/")
	if bucket == "" || name == "" || name == "." || name == ".." || strings.Contains(name, "..") {
		s.filePartial(w, r, bucket, prefix, &flashMessage{Kind: "error", Text: l.t("flash.invalid_name")})
		return
	}
	if err := s.Svc.CreateFolder(r.Context(), bucket, prefix+name+"/"); err != nil {
		s.filePartial(w, r, bucket, prefix, &flashMessage{Kind: "error", Text: l.errorText(err)})
		return
	}
	s.filePartial(w, r, bucket, prefix, &flashMessage{Kind: "ok", Text: l.t("flash.folder_created")})
}

func (s *Server) deleteObject(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	bucket := r.FormValue("bucket")
	prefix := normalizePrefix(r.FormValue("prefix"))
	key := r.FormValue("key")
	if bucket == "" || key == "" {
		s.filePartial(w, r, bucket, prefix, &flashMessage{Kind: "error", Text: l.t("flash.no_bucket")})
		return
	}
	if strings.HasSuffix(key, "/") {
		n, err := s.Svc.DeletePrefix(r.Context(), bucket, key)
		if err != nil {
			s.filePartial(w, r, bucket, prefix, &flashMessage{Kind: "error", Text: l.errorText(err)})
			return
		}
		s.filePartial(w, r, bucket, prefix, &flashMessage{Kind: "ok", Text: l.t("flash.folder_deleted", n)})
		return
	}
	if err := s.Svc.Delete(r.Context(), bucket, key); err != nil && !drive.IsNotFound(err) {
		s.filePartial(w, r, bucket, prefix, &flashMessage{Kind: "error", Text: l.errorText(err)})
		return
	}
	s.filePartial(w, r, bucket, prefix, &flashMessage{Kind: "ok", Text: l.t("flash.object_deleted")})
}

func (s *Server) renameObject(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	bucket := r.FormValue("bucket")
	prefix := normalizePrefix(r.FormValue("prefix"))
	key := r.FormValue("key")
	name := strings.TrimSpace(r.FormValue("name"))
	if err := s.Svc.Rename(r.Context(), bucket, key, name); err != nil {
		s.filePartial(w, r, bucket, prefix, &flashMessage{Kind: "error", Text: l.errorText(err)})
		return
	}
	s.filePartial(w, r, bucket, prefix, &flashMessage{Kind: "ok", Text: l.t("flash.renamed")})
}

func (s *Server) moveObject(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	bucket := r.FormValue("bucket")
	prefix := normalizePrefix(r.FormValue("prefix"))
	key := r.FormValue("key")
	dest := strings.TrimPrefix(strings.TrimSpace(r.FormValue("dest")), "/")
	if err := s.Svc.Move(r.Context(), bucket, key, dest); err != nil {
		s.filePartial(w, r, bucket, prefix, &flashMessage{Kind: "error", Text: l.errorText(err)})
		return
	}
	s.filePartial(w, r, bucket, prefix, &flashMessage{Kind: "ok", Text: l.t("flash.moved")})
}

func (s *Server) copyObject(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	bucket := r.FormValue("bucket")
	prefix := normalizePrefix(r.FormValue("prefix"))
	key := r.FormValue("key")
	destBucket := r.FormValue("dest_bucket")
	if destBucket == "" {
		destBucket = bucket
	}
	destKey := strings.TrimPrefix(strings.TrimSpace(r.FormValue("dest_key")), "/")
	if _, err := s.Svc.Copy(r.Context(), bucket, key, destBucket, destKey); err != nil {
		s.filePartial(w, r, bucket, prefix, &flashMessage{Kind: "error", Text: l.t("flash.copy_failed") + " " + l.errorText(err)})
		return
	}
	s.filePartial(w, r, bucket, prefix, &flashMessage{Kind: "ok", Text: l.t("flash.copied")})
}

func (s *Server) bulkDelete(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	_ = r.ParseForm()
	bucket := r.FormValue("bucket")
	prefix := normalizePrefix(r.FormValue("prefix"))
	keys := r.Form["keys"]
	if len(keys) == 1 && strings.Contains(keys[0], "\n") {
		keys = strings.Split(keys[0], "\n")
	}
	if len(keys) == 0 || len(keys) > 1000 {
		s.filePartial(w, r, bucket, prefix, &flashMessage{Kind: "error", Text: l.t("flash.no_selection")})
		return
	}
	deleted, failed := 0, 0
	var firstErr error
	for _, key := range keys {
		if key == "" {
			continue
		}
		var err error
		if strings.HasSuffix(key, "/") {
			var n int
			n, err = s.Svc.DeletePrefix(r.Context(), bucket, key)
			deleted += n
		} else {
			err = s.Svc.Delete(r.Context(), bucket, key)
			if err == nil || drive.IsNotFound(err) {
				deleted++
			}
		}
		if err != nil && !drive.IsNotFound(err) {
			failed++
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if failed > 0 {
		s.filePartial(w, r, bucket, prefix, &flashMessage{Kind: "error", Text: l.errorText(firstErr)})
		return
	}
	s.filePartial(w, r, bucket, prefix, &flashMessage{Kind: "ok", Text: l.t("flash.bulk_deleted", deleted)})
}

func (s *Server) filePartial(w http.ResponseWriter, r *http.Request, bucket, prefix string, notice *flashMessage) {
	s.filePartialStatus(w, r, bucket, prefix, notice, 0)
}

func (s *Server) filePartialStatus(w http.ResponseWriter, r *http.Request, bucket, prefix string, notice *flashMessage, status int) {
	l := s.t(r)
	b := s.base(w, r, l.t("nav.files"), l.t("files.subtitle"), "files", false)
	if status != 0 {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
	}
	s.renderPartial(w, r, "files_panel", s.buildFiles(r, b, bucket, prefix, "", notice))
}

func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	bucket := r.URL.Query().Get("bucket")
	key := r.URL.Query().Get("key")
	meta, _, err := s.Svc.Stat(r.Context(), bucket, key)
	if err != nil {
		http.Error(w, l.errorText(err), http.StatusNotFound)
		return
	}
	native := drive.IsNativeDoc(meta.ContentType)
	var obj *drive.ObjectReader
	if native {
		obj, err = s.Svc.Export(r.Context(), bucket, key)
	} else {
		obj, err = s.Svc.Get(r.Context(), bucket, key, "")
	}
	if err != nil {
		http.Error(w, l.errorText(err), http.StatusBadGateway)
		return
	}
	defer obj.Body.Close()
	name := filepath.Base(key)
	if native {
		name += ".pdf"
	}
	h := w.Header()
	h.Set("Content-Type", contentType(obj.Object.ContentType))
	if obj.Object.Size >= 0 {
		h.Set("Content-Length", strconv.FormatInt(obj.Object.Size, 10))
	}
	h.Set("ETag", `"`+obj.Object.ETag+`"`)
	h.Set("Cache-Control", "private, no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	disposition := "attachment"
	if r.URL.Query().Get("inline") == "1" {
		disposition = "inline"
		h.Set("Content-Security-Policy", "sandbox")
	}
	h.Set("Content-Disposition", mime.FormatMediaType(disposition, map[string]string{"filename": name}))
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, obj.Body)
}

func contentType(v string) string {
	if v == "" {
		return "application/octet-stream"
	}
	return v
}

// ---------------------------------------------------------------------------
// Buckets

type bucketView struct {
	Name         string
	Pool         bool
	PublicRead   bool
	AccountEmail string
	AccountName  string
	Created      string
	Usage        string
	UsageCount   int64
	UsageTrunc   bool
	UsageCalc    bool
	PublicURL    string
}

type bucketData struct {
	baseData
	Buckets     []bucketView
	Accounts    []*store.Account
	UsageLoaded bool
}

func (s *Server) buckets(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	b := s.base(w, r, l.t("nav.buckets"), l.t("buckets.subtitle"), "buckets", true)
	refs, err := s.Svc.ListBuckets(r.Context())
	if err != nil {
		s.setFlash(w, "error", l.errorText(err))
	}
	accounts, _ := s.Store.ListAccounts(r.Context())
	data := bucketData{baseData: b, Accounts: accounts, UsageLoaded: r.URL.Query().Get("usage") == "1"}
	endpoint := strings.TrimRight(s.s3Endpoint(r), "/")
	for _, ref := range refs {
		v := bucketView{Name: ref.Name, Pool: ref.Pool, PublicRead: ref.PublicRead,
			PublicURL: endpoint + "/" + url.PathEscape(ref.Name)}
		if ref.Account != nil {
			v.AccountEmail = ref.Account.Email
			v.AccountName = ref.Account.Name
		}
		if ref.Row != nil {
			v.Created = formatDate(ref.Row.CreatedAt, l.date)
		}
		if data.UsageLoaded {
			used, count, truncated, err := s.Svc.BucketUsage(r.Context(), ref.Name)
			if err != nil {
				v.Usage = l.t("buckets.usage_error")
			} else {
				v.Usage = humanBytes(used)
				v.UsageCount = count
				v.UsageTrunc = truncated
				v.UsageCalc = true
			}
		}
		data.Buckets = append(data.Buckets, v)
	}
	s.render(w, r, "buckets", data)
}

func (s *Server) createBucket(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	name := strings.ToLower(strings.TrimSpace(r.FormValue("name")))
	account := r.FormValue("account")
	if !drive.ValidBucketName(name) {
		s.setFlash(w, "error", l.t("flash.invalid_bucket"))
		http.Redirect(w, r, "/buckets", http.StatusSeeOther)
		return
	}
	ref, err := s.Svc.CreateBucket(r.Context(), name, account)
	if err != nil {
		s.setFlash(w, "error", l.errorText(err))
		http.Redirect(w, r, "/buckets", http.StatusSeeOther)
		return
	}
	_ = ref
	s.setFlash(w, "ok", l.t("flash.bucket_created", name))
	http.Redirect(w, r, "/buckets", http.StatusSeeOther)
}

func (s *Server) deleteBucket(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	name := r.FormValue("name")
	if err := s.Svc.DeleteBucket(r.Context(), name); err != nil {
		s.setFlash(w, "error", l.errorText(err))
	} else {
		s.setFlash(w, "ok", l.t("flash.bucket_deleted", name))
	}
	http.Redirect(w, r, "/buckets", http.StatusSeeOther)
}

func (s *Server) renameBucket(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	oldName := strings.TrimSpace(r.FormValue("name"))
	newName := strings.ToLower(strings.TrimSpace(r.FormValue("new_name")))
	if !drive.ValidBucketName(newName) {
		s.setFlash(w, "error", l.t("flash.invalid_bucket"))
		http.Redirect(w, r, "/buckets", http.StatusSeeOther)
		return
	}
	if err := s.Svc.RenameBucket(r.Context(), oldName, newName); err != nil {
		s.setFlash(w, "error", l.errorText(err))
	} else {
		s.setFlash(w, "ok", l.t("flash.bucket_renamed", oldName, newName))
	}
	http.Redirect(w, r, "/buckets", http.StatusSeeOther)
}

func (s *Server) togglePublic(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	name := r.FormValue("name")
	public := r.FormValue("public") == "1"
	if err := s.Svc.SetPublicRead(r.Context(), name, public); err != nil {
		s.setFlash(w, "error", l.errorText(err))
	} else if public {
		s.setFlash(w, "ok", l.t("flash.bucket_public", name))
	} else {
		s.setFlash(w, "ok", l.t("flash.bucket_private", name))
	}
	http.Redirect(w, r, "/buckets", http.StatusSeeOther)
}

// ---------------------------------------------------------------------------
// Accounts

type accountsData struct {
	baseData
	Accounts   []accountView
	OAuthReady bool
}

func (s *Server) accounts(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	b := s.base(w, r, l.t("nav.accounts"), l.t("accounts.subtitle"), "accounts", true)
	accounts, _ := s.Store.ListAccounts(r.Context())
	counts := s.bucketCounts(r.Context())
	data := accountsData{baseData: b, OAuthReady: s.oauthReady(r)}
	for _, a := range accounts {
		v := accountView{
			ID: a.ID, Name: a.Name, Email: a.Email, Picture: a.Picture,
			Created: formatDate(a.CreatedAt, l.date), NeedsReauth: a.NeedsReauth,
			BucketCount: counts[a.ID],
		}
		if about, err := s.Svc.AccountQuota(r.Context(), a, false); err != nil {
			v.QuotaErr = err.Error()
			v.Class = "danger"
		} else {
			v.Used, v.Limit = about.Usage, about.Limit
			v.Pct, v.Class = quota(about.Usage, about.Limit)
			v.Warn = v.Class != ""
		}
		data.Accounts = append(data.Accounts, v)
	}
	s.render(w, r, "accounts", data)
}

func (s *Server) renameAccount(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	id := r.FormValue("id")
	name := strings.TrimSpace(r.FormValue("name"))
	if len(name) > 80 {
		name = name[:80]
	}
	if name == "" {
		s.setFlash(w, "error", l.t("flash.invalid_name"))
		http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		return
	}
	if err := s.Store.UpdateAccountName(r.Context(), id, name); err != nil {
		s.setFlash(w, "error", l.errorText(err))
	} else {
		s.setFlash(w, "ok", l.t("flash.account_renamed"))
	}
	http.Redirect(w, r, "/accounts", http.StatusSeeOther)
}

func (s *Server) deleteAccount(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	id := r.FormValue("id")
	buckets, _ := s.Store.ListBuckets(r.Context())
	for _, b := range buckets {
		if b.AccountID == id {
			s.setFlash(w, "error", l.t("flash.buckets_exist"))
			http.Redirect(w, r, "/accounts", http.StatusSeeOther)
			return
		}
	}
	if pooled, err := s.Store.CountPoolObjectsByAccount(r.Context(), id); err == nil && pooled > 0 {
		s.setFlash(w, "error", l.t("flash.account_pool_objects", pooled))
		http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		return
	}
	if uploads, err := s.Store.CountUploadsByAccount(r.Context(), id); err == nil && uploads > 0 {
		s.setFlash(w, "error", l.t("flash.account_uploads", uploads))
		http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		return
	}
	if err := s.Store.DeleteAccount(r.Context(), id); err != nil {
		s.setFlash(w, "error", l.errorText(err))
	} else {
		s.setFlash(w, "ok", l.t("flash.account_deleted"))
	}
	http.Redirect(w, r, "/accounts", http.StatusSeeOther)
}

// ---------------------------------------------------------------------------
// Access keys

type auditView struct {
	When      string
	Op        string
	Bucket    string
	Key       string
	AccessKey string
	Account   string
	Size      int64
	Status    int
	StatusOK  bool
	MS        int64
}

type auditData struct {
	baseData
	Events    []auditView
	Total     int
	Page      int
	Pages     int
	Filter    store.EventFilter
	SinceText string
	UntilText string
	PrevPage  int
	NextPage  int
	HasPrev   bool
	HasNext   bool
	PrevURL   string
	NextURL   string
	ExportURL string
}

func (s *Server) auditFilter(r *http.Request) (store.EventFilter, string, string) {
	q := r.URL.Query()
	f := store.EventFilter{
		Op:        q.Get("op"),
		Bucket:    q.Get("bucket"),
		Key:       q.Get("key"),
		AccessKey: q.Get("access_key"),
		Status:    q.Get("status"),
	}
	sinceText, untilText := q.Get("since"), q.Get("until")
	if t, err := time.Parse("2006-01-02", sinceText); err == nil {
		f.Since = t
	}
	if t, err := time.Parse("2006-01-02", untilText); err == nil {
		f.Until = t.Add(24 * time.Hour)
	}
	return f, sinceText, untilText
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	if s.currentRole(r) != "admin" {
		http.Error(w, "administrator role required", http.StatusForbidden)
		return
	}
	l := s.t(r)
	b := s.base(w, r, l.t("nav.audit"), l.t("audit.subtitle"), "audit", true)
	f, sinceText, untilText := s.auditFilter(r)
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	f.Limit = 100
	f.Offset = (page - 1) * f.Limit
	events, total, err := s.Store.ListEvents(r.Context(), f)
	if err != nil {
		s.setFlash(w, "error", l.errorText(err))
	}
	data := auditData{baseData: b, Total: total, Page: page, Filter: f, SinceText: sinceText, UntilText: untilText}
	data.Pages = (total + f.Limit - 1) / f.Limit
	if data.Pages < 1 {
		data.Pages = 1
	}
	data.PrevPage, data.NextPage = page-1, page+1
	data.HasPrev, data.HasNext = page > 1, page < data.Pages
	q := r.URL.Query()
	q.Set("page", strconv.Itoa(data.PrevPage))
	data.PrevURL = "/audit?" + q.Encode()
	q.Set("page", strconv.Itoa(data.NextPage))
	data.NextURL = "/audit?" + q.Encode()
	q.Del("page")
	data.ExportURL = "/audit/export.csv?" + q.Encode()
	for _, e := range events {
		data.Events = append(data.Events, auditView{
			When: formatDate(e.TS, l.dateTime), Op: e.Op, Bucket: e.Bucket, Key: e.Key,
			AccessKey: e.AccessKey, Account: e.AccountID, Size: e.Bytes, Status: e.Status,
			StatusOK: e.Status < 400, MS: e.MS,
		})
	}
	s.render(w, r, "audit", data)
}

func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

func (s *Server) auditExport(w http.ResponseWriter, r *http.Request) {
	if s.currentRole(r) != "admin" {
		http.Error(w, "administrator role required", http.StatusForbidden)
		return
	}
	f, _, _ := s.auditFilter(r)
	f.Limit = 1000
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="s3drive-audit.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"time", "operation", "status", "access_key", "bucket", "key", "bytes", "account_id", "duration_ms"})
	for {
		events, total, err := s.Store.ListEvents(r.Context(), f)
		if err != nil {
			break
		}
		for _, e := range events {
			_ = cw.Write([]string{
				e.TS.UTC().Format(time.RFC3339), csvSafe(e.Op), strconv.Itoa(e.Status), csvSafe(e.AccessKey),
				csvSafe(e.Bucket), csvSafe(e.Key), strconv.FormatInt(e.Bytes, 10), csvSafe(e.AccountID), strconv.FormatInt(e.MS, 10),
			})
		}
		f.Offset += len(events)
		if len(events) == 0 || f.Offset >= total {
			break
		}
	}
	cw.Flush()
}

type keyView struct {
	AccessKey  string
	Label      string
	Created    string
	LastUsed   string
	Active     bool
	Permission string
	Scope      string
	Expires    string
}

type keysData struct {
	baseData
	Keys     []keyView
	Buckets  []string
	Endpoint string
	Region   string
	Example  string
}

func (s *Server) keys(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	b := s.base(w, r, l.t("nav.keys"), l.t("keys.subtitle"), "keys", true)
	keys, _ := s.Store.ListAccessKeys(r.Context())
	cfg, _ := s.Svc.LoadSettings(r.Context())
	endpoint := s.s3Endpoint(r)
	data := keysData{baseData: b, Endpoint: endpoint, Region: cfg.Region}
	buckets, _ := s.Svc.ListBuckets(r.Context())
	for _, ref := range buckets {
		data.Buckets = append(data.Buckets, ref.Name)
	}
	for _, k := range keys {
		scope := "all buckets"
		if k.Bucket != "" {
			scope = k.Bucket
		}
		if k.Prefix != "" {
			scope += "/" + k.Prefix
		}
		v := keyView{AccessKey: k.AccessKey, Label: k.Label, Active: k.Active,
			Created: formatDate(k.CreatedAt, l.date), Permission: k.Permission, Scope: scope}
		if !k.ExpiresAt.IsZero() {
			v.Expires = formatDate(k.ExpiresAt, l.date)
		}
		if !k.LastUsedAt.IsZero() {
			v.LastUsed = s.shortWhen(l, k.LastUsedAt)
		}
		data.Keys = append(data.Keys, v)
	}
	data.Example = "aws configure set region " + cfg.Region + "\n" +
		"aws configure set aws_access_key_id YOUR_ACCESS_KEY\n" +
		"aws configure set aws_secret_access_key YOUR_SECRET_KEY\n" +
		"aws --endpoint-url " + endpoint + " s3 ls"
	s.render(w, r, "keys", data)
}

func (s *Server) s3Endpoint(r *http.Request) string {
	if s.Cfg.PublicS3URL != "" {
		return s.Cfg.PublicS3URL
	}
	host, port, err := net.SplitHostPort(s.Cfg.S3Addr)
	if err != nil {
		host, port = "", "9000"
		if strings.HasPrefix(s.Cfg.S3Addr, ":") {
			port = strings.TrimPrefix(s.Cfg.S3Addr, ":")
		}
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	scheme := "http"
	if r.TLS != nil || (s.Cfg.TrustProxy && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")) {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}

func (s *Server) createKey(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	label := strings.TrimSpace(r.FormValue("label"))
	permission := strings.ToLower(strings.TrimSpace(r.FormValue("permission")))
	if permission != "ro" {
		permission = "rw"
	}
	bucket := strings.TrimSpace(r.FormValue("bucket"))
	prefix := strings.TrimPrefix(strings.TrimSpace(r.FormValue("prefix")), "/")
	var expires time.Time
	if days, _ := strconv.Atoi(r.FormValue("expires_days")); days > 0 {
		if days > 3650 {
			days = 3650
		}
		expires = time.Now().Add(time.Duration(days) * 24 * time.Hour)
	}
	access, secret := generateKeyPair()
	key := &store.AccessKey{AccessKey: access, Secret: secret, Label: label, Active: true,
		Permission: permission, Bucket: bucket, Prefix: prefix, ExpiresAt: expires}
	if err := s.Store.CreateAccessKey(r.Context(), key); err != nil {
		s.setFlash(w, "error", l.errorText(err))
		http.Redirect(w, r, "/keys", http.StatusSeeOther)
		return
	}
	s.setFlashSecret(w, "ok", l.t("flash.key_created"), access+"  /  "+secret)
	http.Redirect(w, r, "/keys", http.StatusSeeOther)
}

func (s *Server) toggleKey(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	access := r.FormValue("access_key")
	active := r.FormValue("active") == "1"
	if err := s.Store.SetAccessKeyActive(r.Context(), access, active); err != nil {
		s.setFlash(w, "error", l.errorText(err))
	} else {
		s.setFlash(w, "ok", l.t("flash.key_toggled"))
	}
	http.Redirect(w, r, "/keys", http.StatusSeeOther)
}

func escapeKeyPath(key string) string {
	parts := strings.Split(key, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func (s *Server) presign(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	accessKey := strings.TrimSpace(r.FormValue("access_key"))
	bucket := strings.TrimSpace(r.FormValue("bucket"))
	key := strings.TrimPrefix(strings.TrimSpace(r.FormValue("key")), "/")
	method := strings.ToUpper(strings.TrimSpace(r.FormValue("method")))
	if method == "" {
		method = http.MethodGet
	}
	minutes, _ := strconv.Atoi(r.FormValue("expires_minutes"))
	if minutes <= 0 || minutes > 10080 {
		minutes = 15
	}
	if accessKey == "" || bucket == "" || key == "" {
		s.setFlash(w, "error", l.t("flash.presign_fields"))
		http.Redirect(w, r, "/keys", http.StatusSeeOther)
		return
	}
	if method != http.MethodGet && method != http.MethodPut && method != http.MethodHead {
		s.setFlash(w, "error", l.t("flash.presign_method"))
		http.Redirect(w, r, "/keys", http.StatusSeeOther)
		return
	}
	keyRow, err := s.Store.GetAccessKey(r.Context(), accessKey)
	if err != nil || keyRow.Secret == "" || !keyRow.Valid(time.Now()) {
		s.setFlash(w, "error", l.t("flash.presign_key"))
		http.Redirect(w, r, "/keys", http.StatusSeeOther)
		return
	}
	allowed := keyRow.CanRead(bucket, key)
	if method == http.MethodPut {
		allowed = keyRow.CanWrite(bucket, key)
	}
	if !allowed {
		s.setFlash(w, "error", l.t("flash.presign_policy"))
		http.Redirect(w, r, "/keys", http.StatusSeeOther)
		return
	}
	if _, err := s.Svc.Bucket(r.Context(), bucket); err != nil {
		s.setFlash(w, "error", l.errorText(err))
		http.Redirect(w, r, "/keys", http.StatusSeeOther)
		return
	}
	secret := keyRow.Secret
	cfg, _ := s.Svc.LoadSettings(r.Context())
	raw := strings.TrimRight(s.s3Endpoint(r), "/") + "/" + url.PathEscape(bucket) + "/" + escapeKeyPath(key)
	link, err := s3.SignQueryMethod(raw, accessKey, secret, cfg.Region, method, time.Now().Add(time.Duration(minutes)*time.Minute))
	if err != nil {
		s.setFlash(w, "error", l.errorText(err))
		http.Redirect(w, r, "/keys", http.StatusSeeOther)
		return
	}
	s.setFlashSecret(w, "ok", l.t("flash.presigned", minutes), link)
	http.Redirect(w, r, "/keys", http.StatusSeeOther)
}

func (s *Server) deleteKey(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	if err := s.Store.DeleteAccessKey(r.Context(), r.FormValue("access_key")); err != nil {
		s.setFlash(w, "error", l.errorText(err))
	} else {
		s.setFlash(w, "ok", l.t("flash.key_deleted"))
	}
	http.Redirect(w, r, "/keys", http.StatusSeeOther)
}

func generateKeyPair() (string, string) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	raw := make([]byte, 17)
	_, _ = rand.Read(raw)
	var b strings.Builder
	b.WriteString("S3D")
	for _, v := range raw {
		b.WriteByte(alphabet[int(v)%len(alphabet)])
	}
	sec := make([]byte, 30)
	_, _ = rand.Read(sec)
	return b.String(), base64.RawURLEncoding.EncodeToString(sec)
}

// ---------------------------------------------------------------------------
// Settings

type userView struct {
	ID       string
	Username string
	Role     string
	Created  string
	IsSelf   bool
}

type settingsData struct {
	baseData
	OAuthClientID  string
	OAuthSecretSet bool
	RedirectURI    string
	OAuthReady     bool
	PublicURL      string
	Region         string
	PoolName       string
	PoolEnabled    bool
	CORS           string
	SiteName       string
	Namespace      string
	Users          []userView
	CurrentUserID  string
}

func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	if s.currentRole(r) != "admin" {
		http.Error(w, "administrator role required", http.StatusForbidden)
		return
	}
	l := s.t(r)
	b := s.base(w, r, l.t("nav.settings"), l.t("settings.subtitle"), "settings", true)
	cfg, _ := s.Svc.LoadSettings(r.Context())
	oauthCfg, _ := s.Google.OAuthConfig(r.Context(), s.publicURL(r))
	data := settingsData{
		baseData: b, OAuthClientID: oauthCfg.ClientID, OAuthSecretSet: oauthCfg.ClientSecret != "",
		RedirectURI: s.publicURL(r) + "/oauth/callback", OAuthReady: oauthCfg.ClientID != "" && oauthCfg.ClientSecret != "",
		PublicURL: s.publicURL(r), Region: cfg.Region, PoolName: cfg.PoolName, PoolEnabled: cfg.PoolEnabled,
		CORS: cfg.CORSOrigins, SiteName: cfg.SiteName, Namespace: cfg.Namespace,
	}
	if info := s.session(r); info != nil {
		data.CurrentUserID = info.UserID
	}
	users, _ := s.Store.ListUsers(r.Context())
	for _, u := range users {
		data.Users = append(data.Users, userView{
			ID: u.ID, Username: u.Username, Role: u.Role,
			Created: formatDate(u.CreatedAt, l.date), IsSelf: u.ID == data.CurrentUserID,
		})
	}
	s.render(w, r, "settings", data)
}

func validUsername(v string) bool {
	if len(v) < 3 || len(v) > 32 {
		return false
	}
	for _, r := range v {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '.' && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	username := strings.ToLower(strings.TrimSpace(r.FormValue("username")))
	password := r.FormValue("password")
	role := strings.ToLower(strings.TrimSpace(r.FormValue("role")))
	if role != "admin" && role != "viewer" {
		role = "viewer"
	}
	// The first database user must be an administrator. Otherwise an
	// open-mode install could create a viewer first and lock itself out.
	if n, err := s.Store.CountUsers(r.Context()); err == nil && n == 0 {
		role = "admin"
	}
	if !validUsername(username) {
		s.setFlash(w, "error", l.t("flash.invalid_username"))
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	hash, err := secure.HashPassword(password)
	if err != nil {
		s.setFlash(w, "error", l.errorText(err))
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	if err := s.Store.CreateUser(r.Context(), &store.User{Username: username, PasswordHash: hash, Role: role}); err != nil {
		s.setFlash(w, "error", l.errorText(err))
	} else {
		s.setFlash(w, "ok", l.t("flash.user_created", username))
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	id := r.FormValue("id")
	if info := s.session(r); info != nil && info.UserID == id {
		s.setFlash(w, "error", l.t("flash.user_self"))
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	if err := s.Store.DeleteUser(r.Context(), id); err != nil {
		s.setFlash(w, "error", l.errorText(err))
	} else {
		s.setFlash(w, "ok", l.t("flash.user_deleted"))
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) changeUserPassword(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	id := r.FormValue("id")
	password := r.FormValue("password")
	hash, err := secure.HashPassword(password)
	if err != nil {
		s.setFlash(w, "error", l.errorText(err))
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	if err := s.Store.UpdateUserPassword(r.Context(), id, hash); err != nil {
		s.setFlash(w, "error", l.errorText(err))
	} else {
		s.setFlash(w, "ok", l.t("flash.user_password"))
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) saveOAuthSettings(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	secret := strings.TrimSpace(r.FormValue("client_secret"))
	existing, err := s.Google.OAuthConfig(r.Context(), s.publicURL(r))
	if err != nil {
		s.setFlash(w, "error", l.errorText(err))
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	if secret == "" {
		secret = existing.ClientSecret
	}
	if clientID == "" {
		s.setFlash(w, "error", l.t("settings.client_required"))
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	if err := s.Google.SaveOAuthConfig(r.Context(), clientID, secret); err != nil {
		s.setFlash(w, "error", l.errorText(err))
	} else {
		s.setFlash(w, "ok", l.t("flash.settings_saved"))
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) saveServerSettings(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	ctx := r.Context()
	publicURL := strings.TrimRight(strings.TrimSpace(r.FormValue("public_url")), "/")
	if publicURL != "" {
		u, err := url.Parse(publicURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			s.setFlash(w, "error", l.t("settings.public_url_invalid"))
			http.Redirect(w, r, "/settings", http.StatusSeeOther)
			return
		}
	}
	region := strings.TrimSpace(r.FormValue("region"))
	if region == "" {
		region = "us-east-1"
	}
	poolName := strings.ToLower(strings.TrimSpace(r.FormValue("pool_name")))
	if poolName == "" {
		poolName = "pool"
	}
	if !drive.ValidBucketName(poolName) {
		s.setFlash(w, "error", l.t("flash.invalid_bucket"))
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	siteName := strings.TrimSpace(r.FormValue("site_name"))
	if siteName == "" {
		siteName = "s3drive"
	}
	namespace := strings.TrimSpace(r.FormValue("namespace"))
	if namespace == "" {
		namespace = "s3drive"
	}
	if strings.ContainsAny(namespace, `/\`) || len(namespace) > 200 {
		s.setFlash(w, "error", l.t("settings.namespace_invalid"))
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	poolEnabled := "0"
	if r.FormValue("pool_enabled") == "1" {
		poolEnabled = "1"
	}
	oldCfg, _ := s.Svc.LoadSettings(ctx)
	enablingPool := poolEnabled == "1" && (!oldCfg.PoolEnabled || poolName != oldCfg.PoolName)
	if enablingPool {
		if _, err := s.Store.GetBucket(ctx, poolName); err == nil {
			s.setFlash(w, "error", l.t("flash.pool_name_in_use", poolName))
			http.Redirect(w, r, "/settings", http.StatusSeeOther)
			return
		}
	}
	if oldCfg.PoolName != "" && poolName != oldCfg.PoolName {
		if n, err := s.Store.CountPoolObjects(ctx); err == nil && n > 0 {
			s.setFlash(w, "error", l.t("flash.pool_rename_blocked", n))
			http.Redirect(w, r, "/settings", http.StatusSeeOther)
			return
		}
	}
	if oldCfg.Namespace != "" && namespace != oldCfg.Namespace {
		buckets, _ := s.Store.ListBuckets(ctx)
		pooled, _ := s.Store.CountPoolObjects(ctx)
		if len(buckets) > 0 || pooled > 0 {
			s.setFlash(w, "error", l.t("flash.namespace_blocked"))
			http.Redirect(w, r, "/settings", http.StatusSeeOther)
			return
		}
		_ = s.Store.ClearNamespaceIDs(ctx)
	}
	pairs := map[string]string{
		drive.SettingPublicURL:   publicURL,
		drive.SettingRegion:      region,
		drive.SettingPoolName:    poolName,
		drive.SettingPoolEnabled: poolEnabled,
		drive.SettingCORS:        strings.TrimSpace(r.FormValue("cors_origins")),
		drive.SettingSiteName:    siteName,
		drive.SettingNamespace:   namespace,
	}
	for k, v := range pairs {
		if err := s.Store.SetSetting(ctx, k, v); err != nil {
			s.setFlash(w, "error", l.errorText(err))
			http.Redirect(w, r, "/settings", http.StatusSeeOther)
			return
		}
	}
	s.setFlash(w, "ok", l.t("flash.settings_saved"))
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// ---------------------------------------------------------------------------
// Login, language, health

type loginData struct {
	baseData
	Error string
	Next  string
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if s.isAuthed(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	l := s.t(r)
	b := s.base(w, r, l.t("login.title"), "", "", false)
	b.AuthPage = true
	s.render(w, r, "login", loginData{baseData: b, Next: safeNext(r.URL.Query().Get("next"))})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	ip := s.clientIP(r)
	if ok, wait := s.loginAllowed(ip); !ok {
		b := s.base(w, r, l.t("login.title"), "", "", false)
		b.AuthPage = true
		s.render(w, r, "login", loginData{
			baseData: b,
			Error:    l.t("flash.login_locked", int(wait.Minutes())+1),
			Next:     safeNext(r.FormValue("next")),
		})
		return
	}
	password := r.FormValue("password")
	username := strings.TrimSpace(r.FormValue("username"))
	if s.openMode() {
		s.recordLoginSuccess(ip)
		s.setSession(w, r, "env", "admin")
		http.Redirect(w, r, safeNext(r.FormValue("next")), http.StatusSeeOther)
		return
	}
	if s.Cfg.UIPassword != "" && subtleCompare(password, s.Cfg.UIPassword) {
		s.recordLoginSuccess(ip)
		s.setSession(w, r, "env", "admin")
		http.Redirect(w, r, safeNext(r.FormValue("next")), http.StatusSeeOther)
		return
	}
	if username != "" {
		if u, err := s.Store.GetUserByUsername(r.Context(), username); err == nil && secure.VerifyPassword(u.PasswordHash, password) {
			s.recordLoginSuccess(ip)
			s.setSession(w, r, u.ID, u.Role)
			http.Redirect(w, r, safeNext(r.FormValue("next")), http.StatusSeeOther)
			return
		}
	}
	s.recordLoginFailure(ip)
	b := s.base(w, r, l.t("login.title"), "", "", false)
	b.AuthPage = true
	s.render(w, r, "login", loginData{baseData: b, Error: l.t("flash.login_failed"), Next: safeNext(r.FormValue("next"))})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.clearSession(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) setLang(w http.ResponseWriter, r *http.Request) {
	code := strings.ToLower(r.FormValue("lang"))
	if _, ok := langs[code]; !ok {
		code = "en"
	}
	http.SetCookie(w, &http.Cookie{
		Name: "lang", Value: code, Path: "/", MaxAge: 365 * 24 * 60 * 60,
		SameSite: http.SameSiteLaxMode, Secure: s.secureCookie(r),
	})
	http.Redirect(w, r, safeNext(r.Referer()), http.StatusSeeOther)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	accounts, err := s.Store.ListAccounts(r.Context())
	status := "ok"
	needs := 0
	if err != nil {
		status = "degraded"
	}
	for _, a := range accounts {
		if a.NeedsReauth {
			needs++
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, `{"status":"`+status+`","version":"`+config.Version+`","accounts":`+strconv.Itoa(len(accounts))+`,"needs_reauth":`+strconv.Itoa(needs)+`}`)
}

func safeNext(v string) string {
	if v == "" {
		return "/"
	}
	if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
		u, err := url.Parse(v)
		if err != nil {
			return "/"
		}
		v = u.RequestURI()
	}
	if !strings.HasPrefix(v, "/") || strings.HasPrefix(v, "//") || strings.HasPrefix(v, "/login") {
		return "/"
	}
	return v
}

func subtleCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
