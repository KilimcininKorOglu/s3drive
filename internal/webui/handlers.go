package webui

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"s3drive/internal/config"
	"s3drive/internal/drive"
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
}

type filesData struct {
	baseData
	Buckets   []*drive.BucketRef
	Bucket    string
	Prefix    string
	Crumbs    []crumbView
	Folders   []folderView
	Files     []fileView
	ItemCount int
	NextToken string
	Pool      bool
	Notice    *flashMessage
}

func (s *Server) files(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	b := s.base(w, r, l.t("nav.files"), l.t("files.subtitle"), "files", true)
	data := s.buildFiles(r, b, r.URL.Query().Get("bucket"), normalizePrefix(r.URL.Query().Get("prefix")), r.URL.Query().Get("after"), nil)
	s.render(w, r, "files", data)
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
	res, err := s.Svc.List(ctx, bucket, prefix, "/", 1000, after)
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
			data.Files = append(data.Files, fileView{
				Key: o.Key, Name: name, When: s.shortWhen(l, o.Modified),
				Size: o.Size, AccountMail: o.AccountMail,
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
		text := l.t("flash.error", firstErr.Error())
		if ok > 0 {
			text = l.t("flash.uploaded", ok) + " — " + text
		}
		notice = &flashMessage{Kind: "error", Text: text}
	} else {
		notice = &flashMessage{Kind: "ok", Text: l.t("flash.uploaded", ok)}
	}
	s.filePartial(w, r, bucket, prefix, notice)
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
		s.filePartial(w, r, bucket, prefix, &flashMessage{Kind: "error", Text: l.t("flash.error", err.Error())})
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
			s.filePartial(w, r, bucket, prefix, &flashMessage{Kind: "error", Text: l.t("flash.error", err.Error())})
			return
		}
		s.filePartial(w, r, bucket, prefix, &flashMessage{Kind: "ok", Text: l.t("flash.folder_deleted", n)})
		return
	}
	if err := s.Svc.Delete(r.Context(), bucket, key); err != nil && !drive.IsNotFound(err) {
		s.filePartial(w, r, bucket, prefix, &flashMessage{Kind: "error", Text: l.t("flash.error", err.Error())})
		return
	}
	s.filePartial(w, r, bucket, prefix, &flashMessage{Kind: "ok", Text: l.t("flash.object_deleted")})
}

func (s *Server) filePartial(w http.ResponseWriter, r *http.Request, bucket, prefix string, notice *flashMessage) {
	l := s.t(r)
	b := s.base(w, r, l.t("nav.files"), l.t("files.subtitle"), "files", false)
	s.renderPartial(w, r, "files_panel", s.buildFiles(r, b, bucket, prefix, "", notice))
}

func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	bucket := r.URL.Query().Get("bucket")
	key := r.URL.Query().Get("key")
	obj, err := s.Svc.Get(r.Context(), bucket, key, "")
	if err != nil {
		http.Error(w, l.t("flash.error", err.Error()), http.StatusNotFound)
		return
	}
	defer obj.Body.Close()
	name := filepath.Base(key)
	h := w.Header()
	h.Set("Content-Type", contentType(obj.Object.ContentType))
	h.Set("Content-Length", strconv.FormatInt(obj.Object.Size, 10))
	h.Set("ETag", `"`+obj.Object.ETag+`"`)
	h.Set("Cache-Control", "private, no-store")
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
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
	Created      string
}

type bucketData struct {
	baseData
	Buckets  []bucketView
	Accounts []*store.Account
}

func (s *Server) buckets(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	b := s.base(w, r, l.t("nav.buckets"), l.t("buckets.subtitle"), "buckets", true)
	refs, err := s.Svc.ListBuckets(r.Context())
	if err != nil {
		s.setFlash(w, "error", l.t("flash.error", err.Error()))
	}
	accounts, _ := s.Store.ListAccounts(r.Context())
	data := bucketData{baseData: b, Accounts: accounts}
	for _, ref := range refs {
		v := bucketView{Name: ref.Name, Pool: ref.Pool, PublicRead: ref.PublicRead}
		if ref.Account != nil {
			v.AccountEmail = ref.Account.Email
		}
		if ref.Row != nil {
			v.Created = formatDate(ref.Row.CreatedAt, l.date)
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
		s.setFlash(w, "error", l.t("flash.error", err.Error()))
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
		s.setFlash(w, "error", l.t("flash.error", err.Error()))
	} else {
		s.setFlash(w, "ok", l.t("flash.bucket_deleted", name))
	}
	http.Redirect(w, r, "/buckets", http.StatusSeeOther)
}

func (s *Server) togglePublic(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	name := r.FormValue("name")
	public := r.FormValue("public") == "1"
	if err := s.Svc.SetPublicRead(r.Context(), name, public); err != nil {
		s.setFlash(w, "error", l.t("flash.error", err.Error()))
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
	if err := s.Store.DeleteAccount(r.Context(), id); err != nil {
		s.setFlash(w, "error", l.t("flash.error", err.Error()))
	} else {
		s.setFlash(w, "ok", l.t("flash.account_deleted"))
	}
	http.Redirect(w, r, "/accounts", http.StatusSeeOther)
}

// ---------------------------------------------------------------------------
// Access keys

type keyView struct {
	AccessKey string
	Label     string
	Created   string
	LastUsed  string
	Active    bool
}

type keysData struct {
	baseData
	Keys     []keyView
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
	for _, k := range keys {
		v := keyView{AccessKey: k.AccessKey, Label: k.Label, Active: k.Active,
			Created: formatDate(k.CreatedAt, l.date)}
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
	access, secret := generateKeyPair()
	key := &store.AccessKey{AccessKey: access, Secret: secret, Label: label, Active: true}
	if err := s.Store.CreateAccessKey(r.Context(), key); err != nil {
		s.setFlash(w, "error", l.t("flash.error", err.Error()))
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
		s.setFlash(w, "error", l.t("flash.error", err.Error()))
	} else {
		s.setFlash(w, "ok", l.t("flash.key_toggled"))
	}
	http.Redirect(w, r, "/keys", http.StatusSeeOther)
}

func (s *Server) deleteKey(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	if err := s.Store.DeleteAccessKey(r.Context(), r.FormValue("access_key")); err != nil {
		s.setFlash(w, "error", l.t("flash.error", err.Error()))
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
}

func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	b := s.base(w, r, l.t("nav.settings"), l.t("settings.subtitle"), "settings", true)
	cfg, _ := s.Svc.LoadSettings(r.Context())
	oauthCfg, _ := s.Google.OAuthConfig(r.Context(), s.publicURL(r))
	data := settingsData{
		baseData: b, OAuthClientID: oauthCfg.ClientID, OAuthSecretSet: oauthCfg.ClientSecret != "",
		RedirectURI: s.publicURL(r) + "/oauth/callback", OAuthReady: oauthCfg.ClientID != "" && oauthCfg.ClientSecret != "",
		PublicURL: s.publicURL(r), Region: cfg.Region, PoolName: cfg.PoolName, PoolEnabled: cfg.PoolEnabled,
		CORS: cfg.CORSOrigins, SiteName: cfg.SiteName,
	}
	s.render(w, r, "settings", data)
}

func (s *Server) saveOAuthSettings(w http.ResponseWriter, r *http.Request) {
	l := s.t(r)
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	secret := strings.TrimSpace(r.FormValue("client_secret"))
	existing, err := s.Google.OAuthConfig(r.Context(), s.publicURL(r))
	if err != nil {
		s.setFlash(w, "error", l.t("flash.error", err.Error()))
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	if secret == "" {
		secret = existing.ClientSecret
	}
	if clientID == "" {
		s.setFlash(w, "error", l.t("flash.error", l.t("settings.client_id")))
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	if err := s.Google.SaveOAuthConfig(r.Context(), clientID, secret); err != nil {
		s.setFlash(w, "error", l.t("flash.error", err.Error()))
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
			s.setFlash(w, "error", l.t("flash.error", "public URL must start with http:// or https://"))
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
	poolEnabled := "0"
	if r.FormValue("pool_enabled") == "1" {
		poolEnabled = "1"
	}
	pairs := map[string]string{
		drive.SettingPublicURL:   publicURL,
		drive.SettingRegion:      region,
		drive.SettingPoolName:    poolName,
		drive.SettingPoolEnabled: poolEnabled,
		drive.SettingCORS:        strings.TrimSpace(r.FormValue("cors_origins")),
		drive.SettingSiteName:    siteName,
	}
	for k, v := range pairs {
		if err := s.Store.SetSetting(ctx, k, v); err != nil {
			s.setFlash(w, "error", l.t("flash.error", err.Error()))
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
	password := r.FormValue("password")
	if s.Cfg.UIPassword == "" || subtleCompare(password, s.Cfg.UIPassword) {
		s.setSession(w, r)
		http.Redirect(w, r, safeNext(r.FormValue("next")), http.StatusSeeOther)
		return
	}
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
