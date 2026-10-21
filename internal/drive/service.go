// Package drive maps S3 buckets and keys onto Google Drive folders and files.
package drive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"s3drive/internal/google"
	"s3drive/internal/store"
)

// Settings keys stored in the database.
const (
	SettingRegion      = "region"
	SettingPoolEnabled = "pool_enabled"
	SettingPoolName    = "pool_name"
	SettingPublicURL   = "public_url"
	SettingCORS        = "cors_origins"
	SettingSiteName    = "site_name"
)

// Service is the shared operations layer used by both the S3 API and the UI.
type Service struct {
	Store     *store.Store
	Google    *google.Client
	SpoolDir  string
	Log       *slog.Logger
	PublicURL string

	mu     sync.Mutex
	quotas map[string]quotaEntry
	roots  map[string]string
}

type quotaEntry struct {
	about *google.About
	at    time.Time
}

// New builds a Service.
func New(st *store.Store, g *google.Client, spoolDir, publicURL string, log *slog.Logger) *Service {
	return &Service{
		Store: st, Google: g, SpoolDir: spoolDir, PublicURL: publicURL, Log: log,
		quotas: map[string]quotaEntry{},
		roots:  map[string]string{},
	}
}

// Error is a user-facing failure with an S3 error code.
type Error struct {
	Code    string
	Message string
	Status  int
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func newError(code, format string, args ...any) *Error {
	status := http.StatusBadRequest
	switch code {
	case "NoSuchBucket", "NoSuchKey", "NoSuchUpload":
		status = http.StatusNotFound
	case "AccessDenied":
		status = http.StatusForbidden
	case "InternalError":
		status = http.StatusInternalServerError
	case "NotImplemented":
		status = http.StatusNotImplemented
	}
	return &Error{Code: code, Message: fmt.Sprintf(format, args...), Status: status}
}

// CodeOf returns the S3 error code for err, or "InternalError".
func CodeOf(err error) string {
	var de *Error
	if errors.As(err, &de) {
		return de.Code
	}
	return "InternalError"
}

// Settings is the runtime configuration kept in the database.
type Settings struct {
	Region      string
	PoolName    string
	PoolEnabled bool
	PublicURL   string
	CORSOrigins string
	SiteName    string
}

// LoadSettings reads settings, applying defaults.
func (s *Service) LoadSettings(ctx context.Context) (Settings, error) {
	out := Settings{Region: "us-east-1", PoolName: "pool", PoolEnabled: true, PublicURL: s.PublicURL, SiteName: "s3drive"}
	get := func(key string) (string, error) { return s.Store.Setting(ctx, key) }
	var err error
	if v, e := get(SettingRegion); e != nil {
		return out, e
	} else if v != "" {
		out.Region = v
	}
	if v, e := get(SettingPoolName); e != nil {
		return out, e
	} else if v != "" {
		out.PoolName = v
	}
	if v, e := get(SettingPoolEnabled); e != nil {
		return out, e
	} else if v == "0" {
		out.PoolEnabled = false
	}
	if v, e := get(SettingPublicURL); e != nil {
		return out, e
	} else if v != "" {
		out.PublicURL = strings.TrimRight(v, "/")
	}
	if v, e := get(SettingCORS); e != nil {
		return out, e
	} else if v != "" {
		out.CORSOrigins = v
	}
	if v, e := get(SettingSiteName); e != nil {
		return out, e
	} else if v != "" {
		out.SiteName = v
	}
	return out, err
}

// ---------------------------------------------------------------------------
// Bucket resolution

// BucketRef describes a resolved bucket.
type BucketRef struct {
	Name       string
	Pool       bool
	Account    *store.Account
	FolderID   string
	PublicRead bool
	Row        *store.Bucket
}

// Bucket resolves an S3 bucket name, including the virtual pool bucket.
func (s *Service) Bucket(ctx context.Context, name string) (*BucketRef, error) {
	cfg, err := s.LoadSettings(ctx)
	if err != nil {
		return nil, err
	}
	if cfg.PoolEnabled && name == cfg.PoolName {
		return &BucketRef{Name: name, Pool: true}, nil
	}
	row, err := s.Store.GetBucket(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return nil, newError("NoSuchBucket", "bucket %q does not exist", name)
	}
	if err != nil {
		return nil, err
	}
	acct, err := s.Store.GetAccount(ctx, row.AccountID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, newError("NoSuchBucket", "bucket %q has no account", name)
	}
	if err != nil {
		return nil, err
	}
	return &BucketRef{Name: name, Account: acct, FolderID: row.FolderID, PublicRead: row.PublicRead, Row: row}, nil
}

// ListBuckets returns pinned buckets plus the virtual pool bucket.
func (s *Service) ListBuckets(ctx context.Context) ([]*BucketRef, error) {
	cfg, err := s.LoadSettings(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.Store.ListBuckets(ctx)
	if err != nil {
		return nil, err
	}
	accounts, err := s.Store.ListAccounts(ctx)
	if err != nil {
		return nil, err
	}
	byID := map[string]*store.Account{}
	for _, a := range accounts {
		byID[a.ID] = a
	}
	out := make([]*BucketRef, 0, len(rows)+1)
	for _, row := range rows {
		ref := &BucketRef{Name: row.Name, FolderID: row.FolderID, PublicRead: row.PublicRead, Row: row}
		ref.Account = byID[row.AccountID]
		out = append(out, ref)
	}
	if cfg.PoolEnabled && len(accounts) > 0 {
		out = append(out, &BucketRef{Name: cfg.PoolName, Pool: true})
	}
	return out, nil
}

var bucketNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// ValidBucketName applies the S3 DNS-compatible naming rules.
func ValidBucketName(name string) bool {
	if !bucketNameRE.MatchString(name) {
		return false
	}
	return !strings.Contains(name, "..") && !strings.Contains(name, ".-") && !strings.Contains(name, "-.")
}

// CreateBucket creates the Drive folder and the mapping. When accountID is
// empty the account with the most free space is used.
func (s *Service) CreateBucket(ctx context.Context, name, accountID string) (*BucketRef, error) {
	cfg, err := s.LoadSettings(ctx)
	if err != nil {
		return nil, err
	}
	if !ValidBucketName(name) {
		return nil, newError("InvalidBucketName", "invalid bucket name %q", name)
	}
	if cfg.PoolEnabled && name == cfg.PoolName {
		return nil, newError("BucketAlreadyExists", "bucket %q is reserved for the pool", name)
	}
	if _, err := s.Store.GetBucket(ctx, name); err == nil {
		return nil, newError("BucketAlreadyExists", "bucket %q already exists", name)
	}
	acct, err := s.pickAccount(ctx, accountID, 0)
	if err != nil {
		return nil, err
	}
	root, err := s.rootID(ctx, acct)
	if err != nil {
		return nil, err
	}
	folder, err := s.ensureFolder(ctx, acct, root, []string{name})
	if err != nil {
		return nil, err
	}
	row := &store.Bucket{Name: name, AccountID: acct.ID, FolderID: folder}
	if err := s.Store.CreateBucket(ctx, row); err != nil {
		return nil, err
	}
	return &BucketRef{Name: name, Account: acct, FolderID: folder, Row: row}, nil
}

// DeleteBucket removes an empty bucket folder and its mapping.
func (s *Service) DeleteBucket(ctx context.Context, name string) error {
	ref, err := s.Bucket(ctx, name)
	if err != nil {
		return err
	}
	if ref.Pool {
		return newError("AccessDenied", "the pool bucket cannot be deleted")
	}
	res, err := s.List(ctx, name, "", "", 1, "")
	if err != nil {
		return err
	}
	if len(res.Objects) > 0 || len(res.CommonPrefixes) > 0 {
		return newError("BucketNotEmpty", "bucket %q is not empty", name)
	}
	if err := s.Google.Delete(ctx, ref.Account, ref.FolderID); err != nil && !isGoogleNotFound(err) {
		return err
	}
	_ = s.Store.ForgetFolder(ctx, ref.Account.ID, ref.FolderID)
	return s.Store.DeleteBucket(ctx, name)
}

// SetPublicRead toggles anonymous GET/HEAD for a bucket.
func (s *Service) SetPublicRead(ctx context.Context, name string, public bool) error {
	return s.Store.SetBucketPublic(ctx, name, public)
}

// ---------------------------------------------------------------------------
// Folder path resolution

func (s *Service) rootID(ctx context.Context, acct *store.Account) (string, error) {
	if acct.RootID != "" {
		return acct.RootID, nil
	}
	s.mu.Lock()
	root := s.roots[acct.ID]
	s.mu.Unlock()
	if root != "" {
		return root, nil
	}
	root, err := s.Google.RootFolderID(ctx, acct)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.roots[acct.ID] = root
	s.mu.Unlock()
	_ = s.Store.SetAccountRoot(ctx, acct.ID, root)
	acct.RootID = root
	return root, nil
}

// ensureFolder walks (and optionally creates) a chain of folders starting at
// parentID. It uses the SQLite folder cache to avoid Drive lookups.
func (s *Service) ensureFolder(ctx context.Context, acct *store.Account, parentID string, segments []string) (string, error) {
	current := parentID
	for _, seg := range segments {
		if seg == "" {
			continue
		}
		if id, ok, err := s.Store.FolderID(ctx, acct.ID, current, seg); err != nil {
			return "", err
		} else if ok {
			current = id
			continue
		}
		f, err := s.Google.FindChild(ctx, acct, current, seg, true)
		if errors.Is(err, store.ErrNotFound) {
			f, err = s.Google.CreateFolder(ctx, acct, seg, current)
		}
		if err != nil {
			return "", err
		}
		_ = s.Store.CacheFolder(ctx, acct.ID, current, seg, f.ID)
		current = f.ID
	}
	return current, nil
}

// findFolder is ensureFolder without creating anything.
func (s *Service) findFolder(ctx context.Context, acct *store.Account, parentID string, segments []string) (string, error) {
	current := parentID
	for _, seg := range segments {
		if seg == "" {
			continue
		}
		if id, ok, err := s.Store.FolderID(ctx, acct.ID, current, seg); err != nil {
			return "", err
		} else if ok {
			current = id
			continue
		}
		f, err := s.Google.FindChild(ctx, acct, current, seg, true)
		if err != nil {
			return "", err
		}
		_ = s.Store.CacheFolder(ctx, acct.ID, current, seg, f.ID)
		current = f.ID
	}
	return current, nil
}

func splitKey(key string) (dirs []string, name string, err error) {
	if err := ValidateKey(key); err != nil {
		return nil, "", err
	}
	trimmed := strings.TrimSuffix(key, "/")
	if trimmed == "" {
		return nil, "", newError("InvalidObjectName", "empty object key")
	}
	idx := strings.LastIndex(trimmed, "/")
	if idx < 0 {
		return nil, trimmed, nil
	}
	return strings.Split(trimmed[:idx], "/"), trimmed[idx+1:], nil
}

// ValidateKey rejects keys Drive cannot represent safely.
func ValidateKey(key string) error {
	if key == "" {
		return newError("InvalidObjectName", "empty object key")
	}
	if len(key) > 1024 {
		return newError("InvalidObjectName", "object key longer than 1024 bytes")
	}
	if strings.HasPrefix(key, "/") {
		return newError("InvalidObjectName", "object key must not start with /")
	}
	for _, seg := range strings.Split(strings.TrimSuffix(key, "/"), "/") {
		if seg == "" {
			return newError("InvalidObjectName", "object key contains an empty path segment")
		}
		if seg == "." || seg == ".." {
			return newError("InvalidObjectName", "object key contains a relative path segment")
		}
		if strings.ContainsRune(seg, 0) {
			return newError("InvalidObjectName", "object key contains a NUL byte")
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Listing

// Object is one listed S3 object.
type Object struct {
	Key         string
	Size        int64
	Modified    time.Time
	ETag        string
	ContentType string
	AccountID   string
	AccountMail string
	FileID      string
}

// ListResult is one page of a ListObjectsV2 call.
type ListResult struct {
	Objects        []Object
	CommonPrefixes []string
	IsTruncated    bool
	NextAfter      string
	// Scanned is the number of Drive entries inspected; useful in tests.
	Scanned int
}

// List implements S3 ListObjectsV2 semantics (prefix, delimiter, paging).
func (s *Service) List(ctx context.Context, bucketName, prefix, delimiter string, maxKeys int, after string) (*ListResult, error) {
	ref, err := s.Bucket(ctx, bucketName)
	if err != nil {
		return nil, err
	}
	if maxKeys <= 0 || maxKeys > 1000 {
		maxKeys = 1000
	}
	prefix = strings.TrimPrefix(prefix, "/")

	if !ref.Pool {
		dirs, namePrefix, err := splitPrefix(prefix)
		if err != nil {
			return nil, err
		}
		folder, err := s.findFolder(ctx, ref.Account, ref.FolderID, dirs)
		if errors.Is(err, store.ErrNotFound) {
			return &ListResult{}, nil
		}
		if err != nil {
			return nil, err
		}
		res := &ListResult{}
		state := &listState{
			prefix: prefix, namePrefix: namePrefix, delimiter: delimiter,
			after: after, limit: maxKeys, res: res, seen: map[string]bool{},
			account: ref.Account,
		}
		if err := s.walk(ctx, state, folder, keyBase(dirPrefix(prefix))); err != nil && !errors.Is(err, errListStop) {
			return nil, err
		}
		return res, nil
	}

	// Pool: list each account's pool folder and merge.
	accounts, err := s.Store.ListAccounts(ctx)
	if err != nil {
		return nil, err
	}
	dirs, namePrefix, err := splitPrefix(prefix)
	if err != nil {
		return nil, err
	}
	merged := &ListResult{}
	seenKeys := map[string]bool{}
	for _, acct := range accounts {
		root, err := s.rootID(ctx, acct)
		if err != nil {
			continue
		}
		folder, err := s.findFolder(ctx, acct, root, []string{s.poolName(ctx)})
		if err != nil {
			continue
		}
		folder, err = s.findFolder(ctx, acct, folder, dirs)
		if err != nil {
			continue
		}
		part := &ListResult{}
		state := &listState{
			prefix: prefix, namePrefix: namePrefix, delimiter: delimiter,
			after: "", limit: 10000, res: part, seen: map[string]bool{},
			account: acct,
		}
		if err := s.walk(ctx, state, folder, keyBase(dirPrefix(prefix))); err != nil && !errors.Is(err, errListStop) {
			return nil, err
		}
		for _, o := range part.Objects {
			if !seenKeys[o.Key] {
				seenKeys[o.Key] = true
				merged.Objects = append(merged.Objects, o)
			}
		}
		for _, p := range part.CommonPrefixes {
			if !seenKeys[p] {
				seenKeys[p] = true
				merged.CommonPrefixes = append(merged.CommonPrefixes, p)
			}
		}
	}
	// Objects that already have a pool index entry win over duplicates.
	for i, o := range merged.Objects {
		if p, err := s.Store.GetPoolObject(ctx, o.Key); err == nil && p.AccountID != o.AccountID {
			acct := accountByID(accounts, p.AccountID)
			if acct != nil {
				if f, err := s.Google.GetFile(ctx, acct, p.FileID); err == nil {
					merged.Objects[i] = objectFromFile(o.Key, acct, f)
				}
			}
		}
	}
	sort.Slice(merged.Objects, func(i, j int) bool { return merged.Objects[i].Key < merged.Objects[j].Key })
	sort.Strings(merged.CommonPrefixes)

	out := &ListResult{}
	count := 0
	for _, p := range merged.CommonPrefixes {
		if !pastAfter(p, after, delimiter) {
			continue
		}
		if count >= maxKeys {
			out.IsTruncated = true
			break
		}
		out.CommonPrefixes = append(out.CommonPrefixes, p)
		out.NextAfter = p
		count++
	}
	if !out.IsTruncated {
		for _, o := range merged.Objects {
			if !pastAfter(o.Key, after, delimiter) {
				continue
			}
			if count >= maxKeys {
				out.IsTruncated = true
				break
			}
			out.Objects = append(out.Objects, o)
			out.NextAfter = o.Key
			count++
		}
	}
	return out, nil
}

func accountByID(accounts []*store.Account, id string) *store.Account {
	for _, a := range accounts {
		if a.ID == id {
			return a
		}
	}
	return nil
}

func (s *Service) poolName(ctx context.Context) string {
	cfg, err := s.LoadSettings(ctx)
	if err != nil || cfg.PoolName == "" {
		return "pool"
	}
	return cfg.PoolName
}

var errListStop = errors.New("list limit reached")

type listState struct {
	prefix     string
	namePrefix string
	delimiter  string
	after      string
	limit      int
	count      int
	res        *ListResult
	seen       map[string]bool
	account    *store.Account
}

func (st *listState) addObject(o Object) error {
	if !pastAfter(o.Key, st.after, st.delimiter) || st.seen[o.Key] {
		return nil
	}
	if st.count >= st.limit {
		st.res.IsTruncated = true
		return errListStop
	}
	st.seen[o.Key] = true
	st.res.Objects = append(st.res.Objects, o)
	st.res.NextAfter = o.Key
	st.count++
	return nil
}

func (st *listState) addPrefix(p string) error {
	if !pastAfter(p, st.after, st.delimiter) || st.seen[p] {
		return nil
	}
	if st.count >= st.limit {
		st.res.IsTruncated = true
		return errListStop
	}
	st.seen[p] = true
	st.res.CommonPrefixes = append(st.res.CommonPrefixes, p)
	st.res.NextAfter = p
	st.count++
	return nil
}

// walk traverses a Drive folder in name order, which yields S3 key order.
func (s *Service) walk(ctx context.Context, st *listState, folderID, keyBase string) error {
	pageToken := ""
	for {
		files, next, err := s.Google.ListChildren(ctx, st.account, folderID, pageToken)
		if err != nil {
			return err
		}
		st.res.Scanned += len(files)
		for _, f := range files {
			if f.IsFolder {
				if st.delimiter != "" {
					if !strings.HasPrefix(f.Name, st.namePrefix) {
						continue
					}
					rel := f.Name[len(st.namePrefix):] + "/"
					if idx := strings.Index(rel, st.delimiter); idx >= 0 {
						cp := st.prefix + rel[:idx+len(st.delimiter)]
						if err := st.addPrefix(cp); err != nil {
							return err
						}
					}
					continue
				}
				if st.namePrefix == "" || strings.HasPrefix(f.Name, st.namePrefix) {
					if err := s.walk(ctx, st, f.ID, keyBase+f.Name+"/"); err != nil {
						return err
					}
				}
				continue
			}
			if !strings.HasPrefix(f.Name, st.namePrefix) {
				continue
			}
			if f.MimeType == google.FolderMime {
				continue
			}
			o := objectFromFile(keyBase+f.Name, st.account, &f)
			if err := st.addObject(o); err != nil {
				return err
			}
		}
		if next == "" {
			return nil
		}
		pageToken = next
	}
}

func objectFromFile(key string, acct *store.Account, f *google.File) Object {
	etag := f.MD5
	if etag == "" {
		etag = f.ID
	}
	mail := ""
	if acct != nil {
		mail = acct.Email
	}
	return Object{
		Key: key, Size: f.Size, Modified: f.Modified, ETag: etag,
		ContentType: f.MimeType, AccountID: acctID(acct), AccountMail: mail, FileID: f.ID,
	}
}

func acctID(acct *store.Account) string {
	if acct == nil {
		return ""
	}
	return acct.ID
}

func splitPrefix(prefix string) (dirs []string, namePrefix string, err error) {
	if prefix == "" {
		return nil, "", nil
	}
	if strings.HasSuffix(prefix, "/") {
		dirs = strings.Split(strings.TrimSuffix(prefix, "/"), "/")
	} else {
		idx := strings.LastIndex(prefix, "/")
		if idx < 0 {
			return nil, prefix, nil
		}
		dirs = strings.Split(prefix[:idx], "/")
		namePrefix = prefix[idx+1:]
	}
	for _, d := range dirs {
		if d == "" || d == "." || d == ".." {
			return nil, "", newError("InvalidArgument", "invalid prefix %q", prefix)
		}
	}
	return dirs, namePrefix, nil
}

func dirPrefix(prefix string) string {
	idx := strings.LastIndex(prefix, "/")
	if idx < 0 {
		return ""
	}
	return prefix[:idx+1]
}

func keyBase(dir string) string { return dir }

// pastAfter applies S3 continuation semantics. A token that ends with the
// delimiter skips the whole common-prefix group.
func pastAfter(key, after, delimiter string) bool {
	if after == "" {
		return true
	}
	if key <= after {
		return false
	}
	if delimiter != "" && strings.HasSuffix(after, delimiter) && strings.HasPrefix(key, after) {
		return false
	}
	return true
}

func isGoogleNotFound(err error) bool {
	var apiErr *google.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status == http.StatusNotFound
	}
	return errors.Is(err, store.ErrNotFound)
}

// spool copies a reader to a temporary file, returning its path, size and MD5.
func (s *Service) spool(r io.Reader) (path string, size int64, md5hex string, err error) {
	f, err := newSpoolFile(s.SpoolDir)
	if err != nil {
		return "", 0, "", err
	}
	path = f.Name()
	h := newMD5()
	n, err := io.Copy(io.MultiWriter(f, h), r)
	cerr := f.Close()
	if err != nil {
		_ = removeFile(path)
		return "", 0, "", err
	}
	if cerr != nil {
		_ = removeFile(path)
		return "", 0, "", cerr
	}
	return path, n, hexString(h.Sum(nil)), nil
}
