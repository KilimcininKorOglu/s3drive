// Package drive maps S3 buckets and keys onto Google Drive folders and files.
package drive

import (
	"context"
	"encoding/json"
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
	SettingNamespace   = "namespace"
)

const (
	appMarker        = "s3drive"
	markerNamespace  = "namespace"
	markerBucket     = "bucket"
	markerPool       = "pool"
	defaultNamespace = "s3drive"
)

// Service is the shared operations layer used by both the S3 API and the UI.
type Service struct {
	Store     *store.Store
	Google    *google.Client
	SpoolDir  string
	Log       *slog.Logger
	PublicURL string

	// Limits are process-wide guard rails. Zero values disable a limit.
	MaxObjectBytes    int64
	DailyUploadBytes  int64
	MaxUploadsPerAcct int
	DiskReserveBytes  int64

	mu            sync.Mutex
	quotas        map[string]quotaEntry
	roots         map[string]string
	folderLocks   map[string]*keyedLock
	uploadSlots   map[string]chan struct{}
	reserved      map[string]int64
	reserveMu     sync.Mutex
	dailyReserved map[string]int64
	dailyMu       sync.Mutex
}

type quotaEntry struct {
	about *google.About
	at    time.Time
}

// keyedLock is reference counted so locks for one-shot object keys do not
// accumulate in the map for the lifetime of the process.
type keyedLock struct {
	mu   sync.Mutex
	refs int
}

// New builds a Service.
func New(st *store.Store, g *google.Client, spoolDir, publicURL string, log *slog.Logger) *Service {
	return &Service{
		Store: st, Google: g, SpoolDir: spoolDir, PublicURL: publicURL, Log: log,
		quotas:        map[string]quotaEntry{},
		roots:         map[string]string{},
		folderLocks:   map[string]*keyedLock{},
		uploadSlots:   map[string]chan struct{}{},
		reserved:      map[string]int64{},
		dailyReserved: map[string]int64{},
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
	case "BucketAlreadyExists", "BucketAlreadyOwnedByYou", "BucketNotEmpty":
		status = http.StatusConflict
	case "InternalError":
		status = http.StatusInternalServerError
	case "NotImplemented":
		status = http.StatusNotImplemented
	case "EntityTooLarge":
		status = http.StatusRequestEntityTooLarge
	case "InsufficientStorage":
		status = http.StatusInsufficientStorage
	case "SlowDown":
		status = http.StatusServiceUnavailable
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
	Namespace   string
}

// LoadSettings reads settings, applying defaults.
func (s *Service) LoadSettings(ctx context.Context) (Settings, error) {
	out := Settings{Region: "us-east-1", PoolName: "pool", PoolEnabled: true, PublicURL: s.PublicURL, SiteName: "s3drive", Namespace: defaultNamespace}
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
	if v, e := get(SettingNamespace); e != nil {
		return out, e
	} else if v != "" {
		out.Namespace = v
	}
	return out, err
}

// Namespace returns the private Drive root folder name used for all buckets.
func (s *Service) Namespace(ctx context.Context) string {
	cfg, err := s.LoadSettings(ctx)
	if err != nil || strings.TrimSpace(cfg.Namespace) == "" {
		return defaultNamespace
	}
	return cfg.Namespace
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
		if cfg.PoolEnabled && row.Name == cfg.PoolName {
			// The virtual pool shadows a pinned bucket with the same name. Do
			// not advertise both; the settings page can disable the pool.
			continue
		}
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
	if name == cfg.PoolName {
		// Reserve the pool name even while pooling is disabled so enabling it
		// later cannot silently shadow an existing bucket.
		return nil, newError("BucketAlreadyExists", "bucket %q is reserved for the pool", name)
	}
	if _, err := s.Store.GetBucket(ctx, name); err == nil {
		return nil, newError("BucketAlreadyExists", "bucket %q already exists", name)
	}
	acct, err := s.pickAccount(ctx, accountID, 0)
	if err != nil {
		return nil, err
	}
	ns, err := s.ensureNamespace(ctx, acct)
	if err != nil {
		return nil, err
	}
	folder, err := s.ensureOwnedFolder(ctx, acct, ns, name, markerBucket)
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

// RenameBucket renames a pinned bucket's Drive folder and local references.
func (s *Service) RenameBucket(ctx context.Context, oldName, newName string) error {
	if !ValidBucketName(newName) {
		return newError("InvalidBucketName", "invalid bucket name %q", newName)
	}
	ref, err := s.Bucket(ctx, oldName)
	if err != nil {
		return err
	}
	if ref.Pool {
		return newError("AccessDenied", "the pool bucket cannot be renamed")
	}
	cfg, err := s.LoadSettings(ctx)
	if err != nil {
		return err
	}
	if newName == cfg.PoolName {
		return newError("BucketAlreadyExists", "bucket name %q is reserved for the pool", newName)
	}
	if _, err := s.Store.GetBucket(ctx, newName); err == nil {
		return newError("BucketAlreadyExists", "bucket %q already exists", newName)
	}
	ns, err := s.ensureNamespace(ctx, ref.Account)
	if err != nil {
		return err
	}
	if existing, err := s.Google.FindChild(ctx, ref.Account, ns, newName, false); err == nil && existing != nil && existing.ID != ref.FolderID {
		return newError("BucketAlreadyExists", "Drive already contains a folder named %q in the s3drive namespace", newName)
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if err := s.Store.RenameBucket(ctx, oldName, newName); err != nil {
		return err
	}
	if _, err := s.Google.Rename(ctx, ref.Account, ref.FolderID, encodeSegment(newName)); err != nil {
		_ = s.Store.RenameBucket(ctx, newName, oldName)
		return err
	}
	_ = s.Store.ClearFolderCache(ctx, ref.Account.ID)
	return nil
}

// BucketUsage walks a bucket and reports total bytes and object count. The
// scan is bounded so a huge bucket cannot stall the console.
func (s *Service) BucketUsage(ctx context.Context, name string) (bytes, objects int64, truncated bool, err error) {
	cursor := ""
	for scanned := 0; scanned < 200000; {
		page, err := s.List(ctx, name, "", "", 1000, cursor)
		if err != nil {
			return 0, 0, false, err
		}
		scanned += page.Scanned
		for _, o := range page.Objects {
			bytes += o.Size
			objects++
		}
		if !page.IsTruncated {
			return bytes, objects, false, nil
		}
		if scanned >= 200000 {
			return bytes, objects, true, nil
		}
		cursor = page.NextAfter
	}
	return bytes, objects, true, nil
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

// ensureNamespace resolves the private s3drive root. A pre-existing folder
// with the configured name is never adopted unless it carries our private
// appProperties marker.
func (s *Service) ensureNamespace(ctx context.Context, acct *store.Account) (string, error) {
	if acct.NamespaceID != "" {
		return acct.NamespaceID, nil
	}
	root, err := s.rootID(ctx, acct)
	if err != nil {
		return "", err
	}
	name := s.Namespace(ctx)
	unlock := s.lockFolder(acct.ID + ":ns:" + name)
	defer unlock()

	f, err := s.Google.FindChild(ctx, acct, root, name, true)
	switch {
	case errors.Is(err, store.ErrNotFound):
		f, err = s.Google.CreateFolderWithProps(ctx, acct, name, root, map[string]string{appMarker: markerNamespace})
		if err != nil {
			return "", err
		}
	case err != nil:
		return "", err
	case f.AppProperties[appMarker] != markerNamespace:
		return "", newError("AccessDenied",
			"Drive already contains a folder named %q that s3drive did not create; rename it or configure S3DRIVE_NAMESPACE", name)
	}
	if err := s.Store.SetAccountNamespace(ctx, acct.ID, f.ID); err != nil {
		return "", err
	}
	acct.NamespaceID = f.ID
	return f.ID, nil
}

// ensureOwnedFolder finds or creates a namespace child carrying an ownership
// marker. Existing unmarked folders are rejected instead of silently exposed.
func (s *Service) ensureOwnedFolder(ctx context.Context, acct *store.Account, parentID, name, kind string) (string, error) {
	if id, ok, err := s.Store.FolderID(ctx, acct.ID, parentID, name); err != nil {
		return "", err
	} else if ok {
		return id, nil
	}
	unlock := s.lockFolder(acct.ID + ":" + parentID + ":" + name)
	defer unlock()

	f, err := s.Google.FindChild(ctx, acct, parentID, name, true)
	switch {
	case errors.Is(err, store.ErrNotFound):
		f, err = s.Google.CreateFolderWithProps(ctx, acct, name, parentID, map[string]string{appMarker: kind})
		if err != nil {
			return "", err
		}
	case err != nil:
		return "", err
	case f.AppProperties[appMarker] != kind:
		return "", newError("AccessDenied",
			"Drive folder %q already exists but was not created by s3drive; refusing to expose it", name)
	}
	_ = s.Store.CacheFolder(ctx, acct.ID, parentID, name, f.ID)
	return f.ID, nil
}

// lockObjects serializes mutations of the same bucket/key across uploads,
// copies, renames, moves and deletes. Keys are locked in sorted order so two
// multi-key operations cannot deadlock.
func (s *Service) lockObjects(keys ...string) func() {
	sort.Strings(keys)
	unlocks := make([]func(), 0, len(keys))
	for _, key := range keys {
		unlocks = append(unlocks, s.lockFolder("obj:"+key))
	}
	return func() {
		for i := len(unlocks) - 1; i >= 0; i-- {
			unlocks[i]()
		}
	}
}

func (s *Service) lockFolder(key string) func() {
	s.mu.Lock()
	m := s.folderLocks[key]
	if m == nil {
		m = &keyedLock{}
		s.folderLocks[key] = m
	}
	m.refs++
	s.mu.Unlock()
	m.mu.Lock()
	return func() {
		m.mu.Unlock()
		s.mu.Lock()
		m.refs--
		if m.refs == 0 && s.folderLocks[key] == m {
			delete(s.folderLocks, key)
		}
		s.mu.Unlock()
	}
}

// ensureFolder walks (and optionally creates) a chain of folders starting at
// parentID. It uses the SQLite folder cache to avoid Drive lookups.
func (s *Service) ensureFolder(ctx context.Context, acct *store.Account, parentID string, segments []string) (string, error) {
	current := parentID
	for _, seg := range segments {
		diskName := encodeSegment(seg)
		if id, ok, err := s.Store.FolderID(ctx, acct.ID, current, diskName); err != nil {
			return "", err
		} else if ok {
			current = id
			continue
		}
		unlock := s.lockFolder(acct.ID + ":" + current + ":" + diskName)
		// Re-check after waiting for a concurrent creator.
		if id, ok, err := s.Store.FolderID(ctx, acct.ID, current, diskName); err != nil {
			unlock()
			return "", err
		} else if ok {
			unlock()
			current = id
			continue
		}
		f, err := s.Google.FindChild(ctx, acct, current, diskName, true)
		if errors.Is(err, store.ErrNotFound) {
			f, err = s.Google.CreateFolder(ctx, acct, diskName, current)
		}
		unlock()
		if err != nil {
			return "", err
		}
		_ = s.Store.CacheFolder(ctx, acct.ID, current, diskName, f.ID)
		current = f.ID
	}
	return current, nil
}

// findFolder is ensureFolder without creating anything.
func (s *Service) findFolder(ctx context.Context, acct *store.Account, parentID string, segments []string) (string, error) {
	current := parentID
	for _, seg := range segments {
		diskName := encodeSegment(seg)
		if id, ok, err := s.Store.FolderID(ctx, acct.ID, current, diskName); err != nil {
			return "", err
		} else if ok {
			current = id
			continue
		}
		unlock := s.lockFolder(acct.ID + ":" + current + ":" + diskName)
		f, err := s.Google.FindChild(ctx, acct, current, diskName, true)
		if err == nil {
			_ = s.Store.CacheFolder(ctx, acct.ID, current, diskName, f.ID)
		}
		unlock()
		if err != nil {
			return "", err
		}
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
	if strings.ContainsRune(key, 0) {
		return newError("InvalidObjectName", "object key contains a NUL byte")
	}
	for _, seg := range strings.Split(strings.TrimSuffix(key, "/"), "/") {
		if len(encodeSegment(seg)) > 255 {
			return newError("InvalidObjectName", "a path component is too long for Drive's 255-byte limit")
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Listing

// IsNativeDoc reports whether a Drive file is a Google Docs/Sheets/Slides
// item that has no binary body and must be exported instead of downloaded.
func IsNativeDoc(mime string) bool {
	return strings.HasPrefix(mime, "application/vnd.google-apps.") && mime != google.FolderMime
}

// Object is one listed S3 object.
type Object struct {
	Key          string
	Size         int64
	Modified     time.Time
	ETag         string
	ContentType  string
	StorageClass string
	Metadata     map[string]string
	Checksum     string
	AccountID    string
	AccountMail  string
	FileID       string
}

// SetObjectMeta stores S3 metadata (ETag, user headers, storage class).
func (s *Service) SetObjectMeta(ctx context.Context, m store.ObjectMeta) error {
	if m.UpdatedAt.IsZero() {
		m.UpdatedAt = time.Now()
	}
	return s.Store.SetObjectMeta(ctx, m)
}

// ObjectMeta returns stored S3 metadata, if any.
func (s *Service) ObjectMeta(ctx context.Context, bucket, key string) (*store.ObjectMeta, error) {
	return s.Store.GetObjectMeta(ctx, bucket, key)
}

func (s *Service) enrichObject(ctx context.Context, bucket string, o *Object) {
	m, err := s.Store.GetObjectMeta(ctx, bucket, o.Key)
	if err != nil {
		return
	}
	if m.ETag != "" {
		o.ETag = m.ETag
	}
	if m.ContentType != "" {
		o.ContentType = m.ContentType
	}
	if m.StorageClass != "" {
		o.StorageClass = m.StorageClass
	} else {
		o.StorageClass = "STANDARD"
	}
	if m.Checksum != "" {
		o.Checksum = m.Checksum
	}
	if m.Metadata != "" {
		_ = json.Unmarshal([]byte(m.Metadata), &o.Metadata)
	}
	if o.StorageClass == "" {
		o.StorageClass = "STANDARD"
	}
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
	return s.list(ctx, bucketName, prefix, delimiter, maxKeys, after, false)
}

// ListUI is like List but includes native Google Docs/Sheets/Slides, which the
// console can export as PDF. The S3 API never exposes them as objects.
func (s *Service) ListUI(ctx context.Context, bucketName, prefix, delimiter string, maxKeys int, after string) (*ListResult, error) {
	return s.list(ctx, bucketName, prefix, delimiter, maxKeys, after, true)
}

func (s *Service) list(ctx context.Context, bucketName, prefix, delimiter string, maxKeys int, after string, includeDocs bool) (*ListResult, error) {
	ref, err := s.Bucket(ctx, bucketName)
	if err != nil {
		return nil, err
	}
	if maxKeys < 0 || maxKeys > 1000 {
		maxKeys = 1000
	}
	if maxKeys == 0 {
		return &ListResult{}, nil
	}
	if delimiter != "" && delimiter != "/" {
		return s.listWithCustomDelimiter(ctx, bucketName, prefix, delimiter, maxKeys, after)
	}
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
			account: ref.Account, includeDocs: includeDocs,
		}
		if err := s.walk(ctx, state, folder, keyBase(dirPrefix(prefix))); err != nil && !errors.Is(err, errListStop) {
			return nil, err
		}
		for i := range res.Objects {
			s.enrichObject(ctx, bucketName, &res.Objects[i])
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
		ns, err := s.ensureNamespace(ctx, acct)
		if err != nil {
			continue
		}
		folder, err := s.findFolder(ctx, acct, ns, []string{s.poolName(ctx)})
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
			after: after, limit: 0, res: part, seen: map[string]bool{},
			account: acct, includeDocs: includeDocs,
		}
		if err := s.walk(ctx, state, folder, keyBase(dirPrefix(prefix))); err != nil && !errors.Is(err, errListStop) {
			return nil, err
		}
		merged.Scanned += part.Scanned
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

	// S3 orders objects and common prefixes together by key. Emitting all
	// prefixes first would lose keys such as "a.txt" when a page ends at "a/".
	type listItem struct {
		key    string
		prefix bool
		obj    Object
	}
	items := make([]listItem, 0, len(merged.Objects)+len(merged.CommonPrefixes))
	for _, o := range merged.Objects {
		items = append(items, listItem{key: o.Key, obj: o})
	}
	for _, p := range merged.CommonPrefixes {
		items = append(items, listItem{key: p, prefix: true})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].key < items[j].key })

	out := &ListResult{Scanned: merged.Scanned}
	count := 0
	for _, item := range items {
		if !pastAfter(item.key, after, delimiter) {
			continue
		}
		if count >= maxKeys {
			out.IsTruncated = true
			break
		}
		if item.prefix {
			out.CommonPrefixes = append(out.CommonPrefixes, item.key)
		} else {
			out.Objects = append(out.Objects, item.obj)
		}
		out.NextAfter = item.key
		count++
	}
	for i := range out.Objects {
		s.enrichObject(ctx, bucketName, &out.Objects[i])
	}
	return out, nil
}

// Search walks a bucket recursively and returns keys containing query. It is
// intended for the console; S3 clients should use ListObjectsV2 with a prefix.
func (s *Service) Search(ctx context.Context, bucketName, query string, limit int) ([]Object, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var out []Object
	cursor := ""
	for scanned := 0; scanned < 200000; {
		page, err := s.ListUI(ctx, bucketName, "", "", 1000, cursor)
		if err != nil {
			return nil, err
		}
		scanned += page.Scanned
		for _, o := range page.Objects {
			if strings.Contains(strings.ToLower(o.Key), strings.ToLower(query)) {
				out = append(out, o)
				if len(out) >= limit {
					return out, nil
				}
			}
		}
		if !page.IsTruncated {
			break
		}
		cursor = page.NextAfter
	}
	return out, nil
}

// listWithCustomDelimiter implements delimiters other than "/" by walking all
// keys below prefix and grouping them in memory, which is what S3 does
// conceptually. Drive itself only knows folder boundaries.
func (s *Service) listWithCustomDelimiter(ctx context.Context, bucketName, prefix, delimiter string, maxKeys int, after string) (*ListResult, error) {
	var objects []Object
	cursor := ""
	for scanned := 0; scanned < 200000; scanned += 1000 {
		page, err := s.List(ctx, bucketName, prefix, "", 1000, cursor)
		if err != nil {
			return nil, err
		}
		objects = append(objects, page.Objects...)
		if !page.IsTruncated {
			break
		}
		cursor = page.NextAfter
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].Key < objects[j].Key })
	out := &ListResult{}
	seenPrefix := map[string]bool{}
	count := 0
	for _, obj := range objects {
		rest := strings.TrimPrefix(obj.Key, prefix)
		if idx := strings.Index(rest, delimiter); idx >= 0 {
			cp := prefix + rest[:idx+len(delimiter)]
			if seenPrefix[cp] || !pastAfter(cp, after, delimiter) {
				continue
			}
			if count >= maxKeys {
				out.IsTruncated = true
				break
			}
			seenPrefix[cp] = true
			out.CommonPrefixes = append(out.CommonPrefixes, cp)
			out.NextAfter = cp
			count++
			continue
		}
		if !pastAfter(obj.Key, after, delimiter) {
			continue
		}
		if count >= maxKeys {
			out.IsTruncated = true
			break
		}
		out.Objects = append(out.Objects, obj)
		out.NextAfter = obj.Key
		count++
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
	prefix      string
	namePrefix  string
	delimiter   string
	after       string
	limit       int
	count       int
	res         *ListResult
	seen        map[string]bool
	account     *store.Account
	includeDocs bool
}

func (st *listState) addObject(o Object) error {
	if !pastAfter(o.Key, st.after, st.delimiter) || st.seen[o.Key] {
		return nil
	}
	if st.limit > 0 && st.count >= st.limit {
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
	if st.limit > 0 && st.count >= st.limit {
		st.res.IsTruncated = true
		return errListStop
	}
	st.seen[p] = true
	st.res.CommonPrefixes = append(st.res.CommonPrefixes, p)
	st.res.NextAfter = p
	st.count++
	return nil
}

// walk traverses a Drive folder. Drive orders by name, while S3 orders by key;
// appending "/" to folder names makes the two orders agree (for example
// "a.txt" sorts before the common prefix "a/"). Children are collected and
// sorted before recursion so pagination cannot skip an interleaved key.
func (s *Service) walk(ctx context.Context, st *listState, folderID, keyBase string) error {
	var files []google.File
	pageToken := ""
	for {
		page, next, err := s.Google.ListChildren(ctx, st.account, folderID, pageToken)
		if err != nil {
			return err
		}
		st.res.Scanned += len(page)
		files = append(files, page...)
		if next == "" {
			break
		}
		pageToken = next
	}
	sort.SliceStable(files, func(i, j int) bool {
		return listSortName(&files[i]) < listSortName(&files[j])
	})
	for _, f := range files {
		name := decodeSegment(f.Name)
		if f.IsFolder {
			if st.delimiter != "" {
				if !strings.HasPrefix(name, st.namePrefix) {
					continue
				}
				rel := name[len(st.namePrefix):] + "/"
				if idx := strings.Index(rel, st.delimiter); idx >= 0 {
					cp := st.prefix + rel[:idx+len(st.delimiter)]
					if err := st.addPrefix(cp); err != nil {
						return err
					}
				}
				continue
			}
			if st.namePrefix == "" || strings.HasPrefix(name, st.namePrefix) {
				oldPrefix := st.namePrefix
				st.namePrefix = ""
				err := s.walk(ctx, st, f.ID, keyBase+name+"/")
				st.namePrefix = oldPrefix
				if err != nil {
					return err
				}
			}
			continue
		}
		if !strings.HasPrefix(name, st.namePrefix) {
			continue
		}
		if f.MimeType == google.FolderMime || (IsNativeDoc(f.MimeType) && !st.includeDocs) {
			continue
		}
		o := objectFromFile(keyBase+name, st.account, &f)
		if err := st.addObject(o); err != nil {
			return err
		}
	}
	return nil
}

func listSortName(f *google.File) string {
	name := decodeSegment(f.Name)
	if f.IsFolder {
		return name + "/"
	}
	return name
}
func objectFromFile(key string, acct *store.Account, f *google.File) Object {
	etag := f.MD5
	if f.IsFolder {
		etag = "d41d8cd98f00b204e9800998ecf8427e"
	} else if etag == "" {
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
	if err := s.checkSpoolCapacity(); err != nil {
		return "", 0, "", err
	}
	f, err := newSpoolFile(s.SpoolDir)
	if err != nil {
		return "", 0, "", err
	}
	path = f.Name()
	h := newMD5()
	var src io.Reader = r
	if s.MaxObjectBytes > 0 {
		src = io.LimitReader(r, s.MaxObjectBytes+1)
	}
	n, err := io.Copy(io.MultiWriter(f, h), src)
	cerr := f.Close()
	if err != nil {
		_ = removeFile(path)
		return "", 0, "", err
	}
	if cerr != nil {
		_ = removeFile(path)
		return "", 0, "", cerr
	}
	if s.MaxObjectBytes > 0 && n > s.MaxObjectBytes {
		_ = removeFile(path)
		return "", 0, "", newError("EntityTooLarge", "object exceeds the configured %s limit", FormatBytes(s.MaxObjectBytes))
	}
	return path, n, hexString(h.Sum(nil)), nil
}
