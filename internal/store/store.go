// Package store persists accounts, buckets, S3 keys, caches and usage events
// in an embedded SQLite database.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"s3drive/internal/secure"
)

// Store is the application's persistent state.
type Store struct {
	db  *sql.DB
	box *secure.Box
}

// Account is a connected Google account. Secrets are encrypted at rest and
// decrypted transparently by the store.
type Account struct {
	ID           string
	Name         string
	Email        string
	Picture      string
	ClientID     string
	ClientSecret string
	RefreshToken string
	AccessToken  string
	TokenExpiry  time.Time
	RootID       string
	NamespaceID  string
	NeedsReauth  bool
	CreatedAt    time.Time
}

// Bucket maps an S3 bucket to a Google Drive folder owned by one account.
type Bucket struct {
	Name       string
	AccountID  string
	FolderID   string
	PublicRead bool
	CreatedAt  time.Time
}

// AccessKey is an S3 credential pair. Secret is populated only by
// GetAccessKeySecret; listings leave it empty.
type AccessKey struct {
	AccessKey string
	Secret    string
	Label     string
	Active    bool
	// Permission is "rw" or "ro".
	Permission string
	// Bucket restricts the key to one bucket. Empty means every bucket.
	Bucket string
	// Prefix restricts the key to keys beginning with this value.
	Prefix string
	// ExpiresAt is zero for keys that never expire.
	ExpiresAt  time.Time
	CreatedAt  time.Time
	LastUsedAt time.Time
}

// CanRead reports whether the key may read a bucket/key pair.
func (k *AccessKey) CanRead(bucket, key string) bool {
	return k.allows(bucket, key)
}

// CanWrite reports whether the key may mutate a bucket/key pair.
func (k *AccessKey) CanWrite(bucket, key string) bool {
	return k.Permission != "ro" && k.allows(bucket, key)
}

// CanWriteBucket reports whether the key may create/delete a bucket.
func (k *AccessKey) CanWriteBucket(bucket string) bool {
	if k.Permission == "ro" || k.Prefix != "" || (k.Bucket != "" && k.Bucket != bucket) {
		return false
	}
	return true
}

func (k *AccessKey) allows(bucket, key string) bool {
	if k.Bucket != "" && k.Bucket != bucket {
		return false
	}
	return k.Prefix == "" || strings.HasPrefix(key, k.Prefix)
}

// Valid reports whether the key is active and not expired.
func (k *AccessKey) Valid(now time.Time) bool {
	return k.Active && (k.ExpiresAt.IsZero() || now.Before(k.ExpiresAt))
}

// Event is one S3 request, used by the dashboard.
type Event struct {
	ID        int64
	TS        time.Time
	Op        string
	Bucket    string
	Key       string
	AccountID string
	AccessKey string
	Bytes     int64
	Status    int
	MS        int64
}

// ObjectMeta stores S3 semantics that Google Drive does not expose natively
// (multipart ETags, user metadata, storage class and checksums).
type ObjectMeta struct {
	Bucket       string
	Key          string
	ETag         string
	ContentType  string
	StorageClass string
	Metadata     string
	Checksum     string
	UpdatedAt    time.Time
}

// User is a console login. Roles are "admin" (read/write) and "viewer"
// (read-only).
type User struct {
	ID           string
	Username     string
	PasswordHash string
	Role         string
	CreatedAt    time.Time
}

// DriveSession records an unfinished Drive resumable upload session.
type DriveSession struct {
	Bucket     string
	Key        string
	AccountID  string
	SessionURL string
	Identity   string
	Size       int64
	Offset     int64
	UpdatedAt  time.Time
}

// EventFilter selects audit-log rows.
type EventFilter struct {
	Op        string
	Bucket    string
	Key       string
	AccessKey string
	Status    string
	Since     time.Time
	Until     time.Time
	Limit     int
	Offset    int
}

// Upload tracks an in-flight S3 multipart upload.
type Upload struct {
	ID           string
	Bucket       string
	Key          string
	AccountID    string
	ContentType  string
	Metadata     string
	StorageClass string
	Checksum     string
	Size         int64
	CreatedAt    time.Time
}

// PoolObject remembers which account holds a key in the virtual pool bucket.
type PoolObject struct {
	Key       string
	AccountID string
	FileID    string
	Size      int64
	UpdatedAt time.Time
}

// Stats is an aggregate over a time window.
type Stats struct {
	Requests  int64
	Errors    int64
	Bytes     int64
	Uploads   int64
	Downloads int64
}

// Open opens (and migrates) the database at path.
func Open(path string, box *secure.Box) (*Store, error) {
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, box: box}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
	id            TEXT PRIMARY KEY,
	name          TEXT NOT NULL,
	email         TEXT NOT NULL DEFAULT '',
	picture       TEXT NOT NULL DEFAULT '',
	client_id     TEXT NOT NULL DEFAULT '',
	client_secret TEXT NOT NULL DEFAULT '',
	refresh_token TEXT NOT NULL DEFAULT '',
	access_token  TEXT NOT NULL DEFAULT '',
	token_expiry  INTEGER NOT NULL DEFAULT 0,
	root_id       TEXT NOT NULL DEFAULT '',
	needs_reauth  INTEGER NOT NULL DEFAULT 0,
	created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS buckets (
	name        TEXT PRIMARY KEY,
	account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
	folder_id   TEXT NOT NULL,
	public_read INTEGER NOT NULL DEFAULT 0,
	created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_buckets_account ON buckets(account_id);
CREATE TABLE IF NOT EXISTS access_keys (
	access_key   TEXT PRIMARY KEY,
	secret       TEXT NOT NULL,
	label        TEXT NOT NULL DEFAULT '',
	active       INTEGER NOT NULL DEFAULT 1,
	created_at   INTEGER NOT NULL,
	last_used_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS folder_cache (
	account_id TEXT NOT NULL,
	parent_id  TEXT NOT NULL,
	name       TEXT NOT NULL,
	folder_id  TEXT NOT NULL,
	updated_at INTEGER NOT NULL,
	PRIMARY KEY (account_id, parent_id, name)
);
CREATE TABLE IF NOT EXISTS events (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	ts         INTEGER NOT NULL,
	op         TEXT NOT NULL,
	bucket     TEXT NOT NULL DEFAULT '',
	key        TEXT NOT NULL DEFAULT '',
	account_id TEXT NOT NULL DEFAULT '',
	bytes      INTEGER NOT NULL DEFAULT 0,
	status     INTEGER NOT NULL DEFAULT 0,
	ms         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS uploads (
	id           TEXT PRIMARY KEY,
	bucket       TEXT NOT NULL,
	key          TEXT NOT NULL,
	account_id   TEXT NOT NULL,
	content_type TEXT NOT NULL DEFAULT '',
	created_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pool_objects (
	key        TEXT PRIMARY KEY,
	account_id TEXT NOT NULL,
	file_id    TEXT NOT NULL,
	size       INTEGER NOT NULL DEFAULT 0,
	updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_states (
	state      TEXT PRIMARY KEY,
	verifier   TEXT NOT NULL,
	account_id TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL
);
`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}

	// Schema v2 additions. addColumn is a no-op when the column already
	// exists, which keeps upgrades from older databases safe.
	cols := []struct{ table, name, def string }{
		{"accounts", "namespace_id", "TEXT NOT NULL DEFAULT ''"},
		{"access_keys", "permission", "TEXT NOT NULL DEFAULT 'rw'"},
		{"access_keys", "bucket", "TEXT NOT NULL DEFAULT ''"},
		{"access_keys", "prefix", "TEXT NOT NULL DEFAULT ''"},
		{"access_keys", "expires_at", "INTEGER NOT NULL DEFAULT 0"},
		{"events", "access_key", "TEXT NOT NULL DEFAULT ''"},
		{"uploads", "updated_at", "INTEGER NOT NULL DEFAULT 0"},
		{"uploads", "metadata", "TEXT NOT NULL DEFAULT ''"},
		{"uploads", "storage_class", "TEXT NOT NULL DEFAULT ''"},
		{"uploads", "checksum", "TEXT NOT NULL DEFAULT ''"},
		{"uploads", "size", "INTEGER NOT NULL DEFAULT 0"},
	}
	for _, c := range cols {
		if err := s.addColumn(c.table, c.name, c.def); err != nil {
			return fmt.Errorf("migrate %s.%s: %w", c.table, c.name, err)
		}
	}

	const v2 = `
CREATE TABLE IF NOT EXISTS object_meta (
	bucket       TEXT NOT NULL,
	key          TEXT NOT NULL,
	etag         TEXT NOT NULL DEFAULT '',
	content_type TEXT NOT NULL DEFAULT '',
	storage_class TEXT NOT NULL DEFAULT '',
	metadata     TEXT NOT NULL DEFAULT '',
	checksum     TEXT NOT NULL DEFAULT '',
	updated_at   INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (bucket, key)
);
CREATE TABLE IF NOT EXISTS upload_usage (
	account_id TEXT NOT NULL,
	day        TEXT NOT NULL,
	bytes      INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (account_id, day)
);
CREATE TABLE IF NOT EXISTS users (
	id            TEXT PRIMARY KEY,
	username      TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	role          TEXT NOT NULL DEFAULT 'admin',
	created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS drive_sessions (
	bucket       TEXT NOT NULL,
	key          TEXT NOT NULL,
	account_id   TEXT NOT NULL,
	session_url  TEXT NOT NULL,
	identity     TEXT NOT NULL DEFAULT '',
	size         INTEGER NOT NULL DEFAULT 0,
	offset       INTEGER NOT NULL DEFAULT 0,
	updated_at   INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (bucket, key)
);
CREATE INDEX IF NOT EXISTS idx_events_key ON events(bucket, key);
CREATE INDEX IF NOT EXISTS idx_events_access ON events(access_key);
CREATE INDEX IF NOT EXISTS idx_upload_usage_day ON upload_usage(day);
`
	if _, err := s.db.Exec(v2); err != nil {
		return err
	}
	if err := s.addColumn("drive_sessions", "identity", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("migrate drive_sessions.identity: %w", err)
	}
	_, err := s.db.Exec(`PRAGMA user_version = 2`)
	return err
}

func (s *Store) addColumn(table, name, def string) error {
	rows, err := s.db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var cname, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &cname, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if cname == name {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = s.db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + name + ` ` + def)
	return err
}

// Seal encrypts a secret with the instance master key.
func (s *Store) Seal(v string) (string, error) { return s.box.Seal(v) }

// Open decrypts a secret sealed by Seal.
func (s *Store) Open(v string) (string, error) { return s.box.Open(v) }

// NewID returns a random 16-byte hex identifier.
func NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func now() int64 { return time.Now().Unix() }

func fromUnix(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(v, 0)
}

// ---------------------------------------------------------------------------
// Settings

// Setting returns "" when the key is not set.
func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetSetting upserts a setting.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// DeleteSetting removes a setting.
func (s *Store) DeleteSetting(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM settings WHERE key = ?`, key)
	return err
}

// ---------------------------------------------------------------------------
// Accounts

// CreateAccount encrypts secrets and inserts the account.
func (s *Store) CreateAccount(ctx context.Context, a *Account) error {
	if a.ID == "" {
		a.ID = NewID()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now()
	}
	cs, err := s.box.Seal(a.ClientSecret)
	if err != nil {
		return err
	}
	rt, err := s.box.Seal(a.RefreshToken)
	if err != nil {
		return err
	}
	at, err := s.box.Seal(a.AccessToken)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO accounts
		(id,name,email,picture,client_id,client_secret,refresh_token,access_token,token_expiry,root_id,namespace_id,needs_reauth,created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		a.ID, a.Name, a.Email, a.Picture, a.ClientID, cs, rt, at,
		a.TokenExpiry.Unix(), a.RootID, a.NamespaceID, boolInt(a.NeedsReauth), a.CreatedAt.Unix())
	return err
}

const accountCols = `id,name,email,picture,client_id,client_secret,refresh_token,access_token,token_expiry,root_id,namespace_id,needs_reauth,created_at`

func (s *Store) scanAccount(row interface{ Scan(...any) error }) (*Account, error) {
	var a Account
	var secret, refresh, access string
	var expiry, created int64
	var reauth int
	err := row.Scan(&a.ID, &a.Name, &a.Email, &a.Picture, &a.ClientID, &secret, &refresh,
		&access, &expiry, &a.RootID, &a.NamespaceID, &reauth, &created)
	if err != nil {
		return nil, err
	}
	if a.ClientSecret, err = s.box.Open(secret); err != nil {
		return nil, err
	}
	if a.RefreshToken, err = s.box.Open(refresh); err != nil {
		return nil, err
	}
	if a.AccessToken, err = s.box.Open(access); err != nil {
		return nil, err
	}
	a.TokenExpiry = fromUnix(expiry)
	a.CreatedAt = fromUnix(created)
	a.NeedsReauth = reauth != 0
	return &a, nil
}

// GetAccount returns one account.
func (s *Store) GetAccount(ctx context.Context, id string) (*Account, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+accountCols+` FROM accounts WHERE id = ?`, id)
	a, err := s.scanAccount(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

// ListAccounts returns every connected account, oldest first.
func (s *Store) ListAccounts(ctx context.Context) ([]*Account, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+accountCols+` FROM accounts ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Account
	for rows.Next() {
		a, err := s.scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// UpdateAccountTokens stores a refreshed access token.
func (s *Store) UpdateAccountTokens(ctx context.Context, id, access string, expiry time.Time) error {
	enc, err := s.box.Seal(access)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE accounts SET access_token=?, token_expiry=?, needs_reauth=0 WHERE id=?`,
		enc, expiry.Unix(), id)
	return err
}

// SetAccountRoot records the account's "My Drive" folder id.
func (s *Store) SetAccountRoot(ctx context.Context, id, rootID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE accounts SET root_id=? WHERE id=?`, rootID, id)
	return err
}

// UpdateAccountOAuth stores a new refresh token after re-authorization.
func (s *Store) UpdateAccountOAuth(ctx context.Context, id, clientID, clientSecret, refreshToken, accessToken string, expiry time.Time, rootID string) error {
	cs, err := s.box.Seal(clientSecret)
	if err != nil {
		return err
	}
	rt, err := s.box.Seal(refreshToken)
	if err != nil {
		return err
	}
	at, err := s.box.Seal(accessToken)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE accounts SET client_id=?, client_secret=?, refresh_token=?, access_token=?,
		token_expiry=?, root_id=?, needs_reauth=0 WHERE id=?`,
		clientID, cs, rt, at, expiry.Unix(), rootID, id)
	return err
}

// MarkAccountReauth flags an account whose refresh token no longer works.
func (s *Store) MarkAccountReauth(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE accounts SET needs_reauth=1 WHERE id=?`, id)
	return err
}

// UpdateAccountProfile refreshes the identity fields shown in the UI.
func (s *Store) UpdateAccountProfile(ctx context.Context, id, name, email, picture, rootID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE accounts SET name=?, email=?, picture=?, root_id=? WHERE id=?`,
		name, email, picture, rootID, id)
	return err
}

// SetAccountNamespace stores the id of the private s3drive folder root.
func (s *Store) SetAccountNamespace(ctx context.Context, id, namespaceID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE accounts SET namespace_id=? WHERE id=?`, namespaceID, id)
	return err
}

// ClearNamespaceIDs forgets cached namespace folder ids, forcing accounts to
// resolve the configured namespace again on their next request.
func (s *Store) ClearNamespaceIDs(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE accounts SET namespace_id=''`)
	return err
}

// UpdateAccountName changes the display name used in the UI.
func (s *Store) UpdateAccountName(ctx context.Context, id, name string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE accounts SET name=? WHERE id=?`, name, id)
	return err
}

// DeleteAccount removes an account and its buckets. Drive files are untouched.
func (s *Store) DeleteAccount(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM folder_cache WHERE account_id=?`,
		`DELETE FROM drive_sessions WHERE account_id=?`,
		`DELETE FROM accounts WHERE id=?`,
	} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ---------------------------------------------------------------------------
// Buckets

// CreateBucket inserts a bucket mapping.
func (s *Store) CreateBucket(ctx context.Context, b *Bucket) error {
	if b.CreatedAt.IsZero() {
		b.CreatedAt = time.Now()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO buckets(name,account_id,folder_id,public_read,created_at) VALUES(?,?,?,?,?)`,
		b.Name, b.AccountID, b.FolderID, boolInt(b.PublicRead), b.CreatedAt.Unix())
	return err
}

// GetBucket returns a bucket by name.
func (s *Store) GetBucket(ctx context.Context, name string) (*Bucket, error) {
	var b Bucket
	var pub, created int64
	err := s.db.QueryRowContext(ctx, `SELECT name,account_id,folder_id,public_read,created_at FROM buckets WHERE name=?`, name).
		Scan(&b.Name, &b.AccountID, &b.FolderID, &pub, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	b.PublicRead = pub != 0
	b.CreatedAt = fromUnix(created)
	return &b, nil
}

// ListBuckets returns every bucket ordered by name.
func (s *Store) ListBuckets(ctx context.Context) ([]*Bucket, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name,account_id,folder_id,public_read,created_at FROM buckets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Bucket
	for rows.Next() {
		var b Bucket
		var pub, created int64
		if err := rows.Scan(&b.Name, &b.AccountID, &b.FolderID, &pub, &created); err != nil {
			return nil, err
		}
		b.PublicRead = pub != 0
		b.CreatedAt = fromUnix(created)
		out = append(out, &b)
	}
	return out, rows.Err()
}

// SetBucketPublic toggles anonymous read access.
func (s *Store) SetBucketPublic(ctx context.Context, name string, public bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE buckets SET public_read=? WHERE name=?`, boolInt(public), name)
	return err
}

// RenameBucket updates every local reference to a bucket name.
func (s *Store) RenameBucket(ctx context.Context, oldName, newName string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmts := []string{
		`UPDATE buckets SET name=? WHERE name=?`,
		`UPDATE object_meta SET bucket=? WHERE bucket=?`,
		`UPDATE uploads SET bucket=? WHERE bucket=?`,
		`UPDATE drive_sessions SET bucket=? WHERE bucket=?`,
		`UPDATE access_keys SET bucket=? WHERE bucket=?`,
	}
	for _, q := range stmts {
		if _, err := tx.ExecContext(ctx, q, newName, oldName); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteBucket removes a bucket mapping.
func (s *Store) DeleteBucket(ctx context.Context, name string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM buckets WHERE name=?`, name)
	if err != nil {
		return err
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM object_meta WHERE bucket=?`, name)
	_, _ = s.db.ExecContext(ctx, `DELETE FROM uploads WHERE bucket=?`, name)
	_, _ = s.db.ExecContext(ctx, `DELETE FROM drive_sessions WHERE bucket=?`, name)
	return nil
}

// ---------------------------------------------------------------------------
// S3 access keys

// CreateAccessKey stores an encrypted secret.
func (s *Store) CreateAccessKey(ctx context.Context, k *AccessKey) error {
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now()
	}
	enc, err := s.box.Seal(k.Secret)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO access_keys(access_key,secret,label,active,permission,bucket,prefix,expires_at,created_at,last_used_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		k.AccessKey, enc, k.Label, boolInt(k.Active), k.Permission, k.Bucket, k.Prefix,
		unixOrZero(k.ExpiresAt), k.CreatedAt.Unix(), unixOrZero(k.LastUsedAt))
	return err
}

const accessKeyCols = `access_key,secret,label,active,permission,bucket,prefix,expires_at,created_at,last_used_at`

func (s *Store) scanAccessKey(row interface{ Scan(...any) error }) (*AccessKey, error) {
	var k AccessKey
	var enc string
	var active, expires, created, used int64
	if err := row.Scan(&k.AccessKey, &enc, &k.Label, &active, &k.Permission,
		&k.Bucket, &k.Prefix, &expires, &created, &used); err != nil {
		return nil, err
	}
	secret, err := s.box.Open(enc)
	if err != nil {
		return nil, err
	}
	k.Secret = secret
	k.Active = active != 0
	k.ExpiresAt = fromUnix(expires)
	k.CreatedAt = fromUnix(created)
	k.LastUsedAt = fromUnix(used)
	if k.Permission == "" {
		k.Permission = "rw"
	}
	return &k, nil
}

// GetAccessKey returns a key with its decrypted secret.
func (s *Store) GetAccessKey(ctx context.Context, accessKey string) (*AccessKey, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+accessKeyCols+` FROM access_keys WHERE access_key=?`, accessKey)
	k, err := s.scanAccessKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return k, err
}

// GetAccessKeySecret returns the decrypted secret for signature checks.
func (s *Store) GetAccessKeySecret(ctx context.Context, accessKey string) (string, bool, error) {
	k, err := s.GetAccessKey(ctx, accessKey)
	if err != nil {
		return "", false, err
	}
	return k.Secret, k.Active, nil
}

// ListAccessKeys returns keys without their secrets.
func (s *Store) ListAccessKeys(ctx context.Context) ([]*AccessKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+accessKeyCols+` FROM access_keys ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AccessKey
	for rows.Next() {
		k, err := s.scanAccessKey(rows)
		if err != nil {
			return nil, err
		}
		k.Secret = ""
		out = append(out, k)
	}
	return out, rows.Err()
}

// TouchAccessKey records key usage (best effort).
func (s *Store) TouchAccessKey(ctx context.Context, accessKey string) {
	_, _ = s.db.ExecContext(ctx, `UPDATE access_keys SET last_used_at=? WHERE access_key=?`, now(), accessKey)
}

// SetAccessKeyActive enables or disables a key.
func (s *Store) SetAccessKeyActive(ctx context.Context, accessKey string, active bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE access_keys SET active=? WHERE access_key=?`, boolInt(active), accessKey)
	return err
}

// DeleteAccessKey removes a key.
func (s *Store) DeleteAccessKey(ctx context.Context, accessKey string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM access_keys WHERE access_key=?`, accessKey)
	return err
}

// HasActiveAccessKey reports whether at least one usable key exists.
func (s *Store) HasActiveAccessKey(ctx context.Context) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM access_keys WHERE active=1`).Scan(&n)
	return n > 0, err
}

// ---------------------------------------------------------------------------
// Folder cache

// FolderID returns a cached Drive folder id.
func (s *Store) FolderID(ctx context.Context, accountID, parentID, name string) (string, bool, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT folder_id FROM folder_cache WHERE account_id=? AND parent_id=? AND name=?`,
		accountID, parentID, name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return id, err == nil, err
}

// CacheFolder records a resolved folder id.
func (s *Store) CacheFolder(ctx context.Context, accountID, parentID, name, folderID string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO folder_cache(account_id,parent_id,name,folder_id,updated_at) VALUES(?,?,?,?,?)
		ON CONFLICT(account_id,parent_id,name) DO UPDATE SET folder_id=excluded.folder_id,updated_at=excluded.updated_at`,
		accountID, parentID, name, folderID, now())
	return err
}

// ForgetFolder removes one cached folder id.
func (s *Store) ForgetFolder(ctx context.Context, accountID, folderID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM folder_cache WHERE account_id=? AND (folder_id=? OR parent_id=?)`,
		accountID, folderID, folderID)
	return err
}

// ClearFolderCache drops every cached folder path for one account after a
// rename or move that invalidates parent/name pairs.
func (s *Store) ClearFolderCache(ctx context.Context, accountID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM folder_cache WHERE account_id=?`, accountID)
	return err
}

// CacheFolderCount is the number of cached folder ids.
func (s *Store) CacheFolderCount(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM folder_cache`).Scan(&n)
	return n, err
}

// ---------------------------------------------------------------------------
// Events

// AddEvent records one request.
func (s *Store) AddEvent(ctx context.Context, e Event) error {
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO events(ts,op,bucket,key,account_id,access_key,bytes,status,ms)
		VALUES(?,?,?,?,?,?,?,?,?)`,
		e.TS.Unix(), e.Op, e.Bucket, e.Key, e.AccountID, e.AccessKey, e.Bytes, e.Status, e.MS)
	return err
}

const eventCols = `id,ts,op,bucket,key,account_id,access_key,bytes,status,ms`

func scanEvent(row interface{ Scan(...any) error }) (*Event, error) {
	var e Event
	var ts int64
	if err := row.Scan(&e.ID, &ts, &e.Op, &e.Bucket, &e.Key, &e.AccountID,
		&e.AccessKey, &e.Bytes, &e.Status, &e.MS); err != nil {
		return nil, err
	}
	e.TS = fromUnix(ts)
	return &e, nil
}

// RecentEvents returns the newest events.
func (s *Store) RecentEvents(ctx context.Context, limit int) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+eventCols+` FROM events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *e)
	}
	return out, rows.Err()
}

// ListEvents returns audit rows matching f and the total count of matches.
func (s *Store) ListEvents(ctx context.Context, f EventFilter) ([]Event, int, error) {
	var where []string
	var args []any
	if f.Op != "" {
		where = append(where, `op = ?`)
		args = append(args, f.Op)
	}
	if f.Bucket != "" {
		where = append(where, `bucket = ?`)
		args = append(args, f.Bucket)
	}
	if f.Key != "" {
		where = append(where, `key LIKE ? ESCAPE '\'`)
		args = append(args, likePrefix(f.Key))
	}
	if f.AccessKey != "" {
		where = append(where, `access_key = ?`)
		args = append(args, f.AccessKey)
	}
	if f.Status == "ok" {
		where = append(where, `status < 400`)
	} else if f.Status == "error" {
		where = append(where, `status >= 400`)
	}
	if !f.Since.IsZero() {
		where = append(where, `ts >= ?`)
		args = append(args, f.Since.Unix())
	}
	if !f.Until.IsZero() {
		where = append(where, `ts < ?`)
		args = append(args, f.Until.Unix())
	}
	clause := ""
	if len(where) > 0 {
		clause = ` WHERE ` + strings.Join(where, ` AND `)
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	q := `SELECT ` + eventCols + ` FROM events` + clause + ` ORDER BY id DESC LIMIT ? OFFSET ?`
	rows, err := s.db.QueryContext(ctx, q, append(args, limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *e)
	}
	return out, total, rows.Err()
}

// StatsSince aggregates events newer than t.
func (s *Store) StatsSince(ctx context.Context, t time.Time) (Stats, error) {
	var st Stats
	err := s.db.QueryRowContext(ctx, `SELECT
		COUNT(*),
		COALESCE(SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END),0),
		COALESCE(SUM(bytes),0),
		COALESCE(SUM(CASE WHEN op IN ('PutObject','UploadPart','CompleteMultipartUpload') THEN 1 ELSE 0 END),0),
		COALESCE(SUM(CASE WHEN op IN ('GetObject','HeadObject') THEN 1 ELSE 0 END),0)
		FROM events WHERE ts >= ?`, t.Unix()).Scan(&st.Requests, &st.Errors, &st.Bytes, &st.Uploads, &st.Downloads)
	return st, err
}

// PruneEvents keeps the event log bounded.
func (s *Store) PruneEvents(ctx context.Context, olderThan time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE ts < ?`, olderThan.Unix())
	return err
}

// ---------------------------------------------------------------------------
// Multipart uploads

// CreateUpload stores an in-flight upload.
func (s *Store) CreateUpload(ctx context.Context, u *Upload) error {
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO uploads(id,bucket,key,account_id,content_type,metadata,storage_class,checksum,size,created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		u.ID, u.Bucket, u.Key, u.AccountID, u.ContentType, u.Metadata, u.StorageClass, u.Checksum, u.Size, u.CreatedAt.Unix())
	return err
}

const uploadCols = `id,bucket,key,account_id,content_type,metadata,storage_class,checksum,size,created_at`

func scanUpload(row interface{ Scan(...any) error }) (*Upload, error) {
	var u Upload
	var created int64
	if err := row.Scan(&u.ID, &u.Bucket, &u.Key, &u.AccountID, &u.ContentType,
		&u.Metadata, &u.StorageClass, &u.Checksum, &u.Size, &created); err != nil {
		return nil, err
	}
	u.CreatedAt = fromUnix(created)
	return &u, nil
}

// GetUpload returns an upload by id.
func (s *Store) GetUpload(ctx context.Context, id, bucket, key string) (*Upload, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+uploadCols+` FROM uploads WHERE id=? AND bucket=? AND key=?`, id, bucket, key)
	u, err := scanUpload(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// GetUploadByID returns a multipart upload regardless of bucket/key.
func (s *Store) GetUploadByID(ctx context.Context, id string) (*Upload, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+uploadCols+` FROM uploads WHERE id=?`, id)
	u, err := scanUpload(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// CountUploadsByAccount counts in-flight multipart uploads pinned to an account.
func (s *Store) CountUploadsByAccount(ctx context.Context, accountID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM uploads WHERE account_id=?`, accountID).Scan(&n)
	return n, err
}

// ListUploads returns in-flight uploads for a bucket ("" for all).
func (s *Store) ListUploads(ctx context.Context, bucket string) ([]*Upload, error) {
	q := `SELECT ` + uploadCols + ` FROM uploads`
	args := []any{}
	if bucket != "" {
		q += ` WHERE bucket=?`
		args = append(args, bucket)
	}
	q += ` ORDER BY created_at`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Upload
	for rows.Next() {
		u, err := scanUpload(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// DeleteUpload removes an upload record.
func (s *Store) DeleteUpload(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM uploads WHERE id=?`, id)
	return err
}

// TouchUpload records activity so abandoned-upload cleanup does not abort a
// large multipart upload that is still making progress.
func (s *Store) TouchUpload(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE uploads SET updated_at=? WHERE id=?`, now(), id)
	return err
}

// StaleUploads returns multipart uploads older than t.
func (s *Store) StaleUploads(ctx context.Context, t time.Time) ([]*Upload, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+uploadCols+` FROM uploads
		WHERE COALESCE(NULLIF(updated_at,0), created_at) < ? ORDER BY created_at`, t.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Upload
	for rows.Next() {
		u, err := scanUpload(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Object metadata

// SetObjectMeta upserts S3 metadata for an object.
func (s *Store) SetObjectMeta(ctx context.Context, m ObjectMeta) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO object_meta(bucket,key,etag,content_type,storage_class,metadata,checksum,updated_at)
		VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(bucket,key) DO UPDATE SET etag=excluded.etag,content_type=excluded.content_type,
		storage_class=excluded.storage_class,metadata=excluded.metadata,checksum=excluded.checksum,
		updated_at=excluded.updated_at`,
		m.Bucket, m.Key, m.ETag, m.ContentType, m.StorageClass, m.Metadata, m.Checksum, now())
	return err
}

// GetObjectMeta returns the stored S3 metadata for an object.
func (s *Store) GetObjectMeta(ctx context.Context, bucket, key string) (*ObjectMeta, error) {
	var m ObjectMeta
	var updated int64
	err := s.db.QueryRowContext(ctx, `SELECT bucket,key,etag,content_type,storage_class,metadata,checksum,updated_at
		FROM object_meta WHERE bucket=? AND key=?`, bucket, key).
		Scan(&m.Bucket, &m.Key, &m.ETag, &m.ContentType, &m.StorageClass, &m.Metadata, &m.Checksum, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	m.UpdatedAt = fromUnix(updated)
	return &m, nil
}

// RenameObjectMeta moves S3 metadata when an object key changes.
func (s *Store) RenameObjectMeta(ctx context.Context, bucket, oldKey, newKey string) error {
	if oldKey == newKey {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var m ObjectMeta
	var updated int64
	err = tx.QueryRowContext(ctx, `SELECT bucket,key,etag,content_type,storage_class,metadata,checksum,updated_at
		FROM object_meta WHERE bucket=? AND key=?`, bucket, oldKey).
		Scan(&m.Bucket, &m.Key, &m.ETag, &m.ContentType, &m.StorageClass, &m.Metadata, &m.Checksum, &updated)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil {
		if _, err := tx.ExecContext(ctx, `INSERT INTO object_meta(bucket,key,etag,content_type,storage_class,metadata,checksum,updated_at)
			VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(bucket,key) DO UPDATE SET etag=excluded.etag,
			content_type=excluded.content_type,storage_class=excluded.storage_class,metadata=excluded.metadata,
			checksum=excluded.checksum,updated_at=excluded.updated_at`,
			bucket, newKey, m.ETag, m.ContentType, m.StorageClass, m.Metadata, m.Checksum, now()); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM object_meta WHERE bucket=? AND key=?`, bucket, oldKey); err != nil {
		return err
	}
	return tx.Commit()
}

// RenamePoolObject updates the location index when a pooled key changes.
func (s *Store) RenamePoolObject(ctx context.Context, oldKey, newKey string) error {
	if oldKey == newKey {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var p PoolObject
	var updated int64
	err = tx.QueryRowContext(ctx, `SELECT key,account_id,file_id,size,updated_at FROM pool_objects WHERE key=?`, oldKey).
		Scan(&p.Key, &p.AccountID, &p.FileID, &p.Size, &updated)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil {
		if _, err := tx.ExecContext(ctx, `INSERT INTO pool_objects(key,account_id,file_id,size,updated_at) VALUES(?,?,?,?,?)
			ON CONFLICT(key) DO UPDATE SET account_id=excluded.account_id,file_id=excluded.file_id,
			size=excluded.size,updated_at=excluded.updated_at`,
			newKey, p.AccountID, p.FileID, p.Size, now()); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM pool_objects WHERE key=?`, oldKey); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteObjectMeta removes metadata for one object or a key prefix when key
// ends with "/".
func (s *Store) DeleteObjectMeta(ctx context.Context, bucket, key string) error {
	if strings.HasSuffix(key, "/") {
		_, err := s.db.ExecContext(ctx, `DELETE FROM object_meta WHERE bucket=? AND key LIKE ? ESCAPE '\'`,
			bucket, likePrefix(key))
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM object_meta WHERE bucket=? AND key=?`, bucket, key)
	return err
}

// ---------------------------------------------------------------------------
// Upload quota

// AddUploadUsage adds bytes to today's per-account upload counter.
func (s *Store) AddUploadUsage(ctx context.Context, accountID string, bytes int64) error {
	if bytes <= 0 {
		return nil
	}
	day := time.Now().UTC().Format("2006-01-02")
	_, err := s.db.ExecContext(ctx, `INSERT INTO upload_usage(account_id,day,bytes) VALUES(?,?,?)
		ON CONFLICT(account_id,day) DO UPDATE SET bytes=bytes+excluded.bytes`, accountID, day, bytes)
	return err
}

// UploadUsageToday returns today's uploaded byte count for an account.
func (s *Store) UploadUsageToday(ctx context.Context, accountID string) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(bytes,0) FROM upload_usage WHERE account_id=? AND day=?`,
		accountID, time.Now().UTC().Format("2006-01-02")).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return n, err
}

// PruneUploadUsage removes counters older than t.
func (s *Store) PruneUploadUsage(ctx context.Context, t time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM upload_usage WHERE day < ?`, t.UTC().Format("2006-01-02"))
	return err
}

// ---------------------------------------------------------------------------
// Resumable Drive sessions

// PutDriveSession records an unfinished resumable upload.
func (s *Store) PutDriveSession(ctx context.Context, d DriveSession) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO drive_sessions(bucket,key,account_id,session_url,identity,size,offset,updated_at)
		VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(bucket,key) DO UPDATE SET account_id=excluded.account_id,session_url=excluded.session_url,
		identity=excluded.identity,size=excluded.size,offset=excluded.offset,updated_at=excluded.updated_at`,
		d.Bucket, d.Key, d.AccountID, d.SessionURL, d.Identity, d.Size, d.Offset, now())
	return err
}

// GetDriveSession returns a saved resumable session.
func (s *Store) GetDriveSession(ctx context.Context, bucket, key string) (*DriveSession, error) {
	var d DriveSession
	var updated int64
	err := s.db.QueryRowContext(ctx, `SELECT bucket,key,account_id,session_url,identity,size,offset,updated_at
		FROM drive_sessions WHERE bucket=? AND key=?`, bucket, key).
		Scan(&d.Bucket, &d.Key, &d.AccountID, &d.SessionURL, &d.Identity, &d.Size, &d.Offset, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d.UpdatedAt = fromUnix(updated)
	return &d, nil
}

// DeleteDriveSession removes a completed or abandoned session.
func (s *Store) DeleteDriveSession(ctx context.Context, bucket, key string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM drive_sessions WHERE bucket=? AND key=?`, bucket, key)
	return err
}

// PruneDriveSessions removes unfinished sessions older than t.
func (s *Store) PruneDriveSessions(ctx context.Context, t time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM drive_sessions WHERE updated_at < ?`, t.Unix())
	return err
}

// ---------------------------------------------------------------------------
// Console users

// CountUsers returns the number of console users.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CreateUser inserts a console user.
func (s *Store) CreateUser(ctx context.Context, u *User) error {
	if u.ID == "" {
		u.ID = NewID()
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now()
	}
	if u.Role == "" {
		u.Role = "viewer"
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO users(id,username,password_hash,role,created_at) VALUES(?,?,?,?,?)`,
		u.ID, strings.ToLower(strings.TrimSpace(u.Username)), u.PasswordHash, u.Role, u.CreatedAt.Unix())
	return err
}

// GetUserByID looks up a console user by id.
func (s *Store) GetUserByID(ctx context.Context, id string) (*User, error) {
	var u User
	var created int64
	err := s.db.QueryRowContext(ctx, `SELECT id,username,password_hash,role,created_at FROM users WHERE id=?`, id).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.CreatedAt = fromUnix(created)
	return &u, nil
}

// GetUserByUsername looks up a console user.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	var u User
	var created int64
	err := s.db.QueryRowContext(ctx, `SELECT id,username,password_hash,role,created_at FROM users WHERE username=?`,
		strings.ToLower(strings.TrimSpace(username))).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.CreatedAt = fromUnix(created)
	return &u, nil
}

// ListUsers returns console users.
func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,username,password_hash,role,created_at FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		var u User
		var created int64
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &created); err != nil {
			return nil, err
		}
		u.CreatedAt = fromUnix(created)
		out = append(out, &u)
	}
	return out, rows.Err()
}

// UpdateUserPassword changes a user's password hash.
func (s *Store) UpdateUserPassword(ctx context.Context, id, hash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash=? WHERE id=?`, hash, id)
	return err
}

// DeleteUser removes a console user.
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id=?`, id)
	return err
}

// ---------------------------------------------------------------------------
// Pool object index

// PutPoolObject upserts the account/file location for a pooled key.
func (s *Store) PutPoolObject(ctx context.Context, p PoolObject) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO pool_objects(key,account_id,file_id,size,updated_at) VALUES(?,?,?,?,?)
		ON CONFLICT(key) DO UPDATE SET account_id=excluded.account_id, file_id=excluded.file_id,
		size=excluded.size, updated_at=excluded.updated_at`,
		p.Key, p.AccountID, p.FileID, p.Size, now())
	return err
}

// GetPoolObject returns the indexed location of a pooled key.
func (s *Store) GetPoolObject(ctx context.Context, key string) (*PoolObject, error) {
	var p PoolObject
	var updated int64
	err := s.db.QueryRowContext(ctx, `SELECT key,account_id,file_id,size,updated_at FROM pool_objects WHERE key=?`, key).
		Scan(&p.Key, &p.AccountID, &p.FileID, &p.Size, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.UpdatedAt = fromUnix(updated)
	return &p, nil
}

// DeletePoolObject removes a pooled key.
func (s *Store) DeletePoolObject(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM pool_objects WHERE key=?`, key)
	return err
}

// CountPoolObjectsByAccount counts indexed pool objects located on accountID.
func (s *Store) CountPoolObjectsByAccount(ctx context.Context, accountID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pool_objects WHERE account_id=?`, accountID).Scan(&n)
	return n, err
}

// CountPoolObjects returns the number of indexed pooled objects.
func (s *Store) CountPoolObjects(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pool_objects`).Scan(&n)
	return n, err
}

// ListPoolObjects returns indexed keys with a prefix.
func (s *Store) ListPoolObjects(ctx context.Context, prefix string) ([]PoolObject, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key,account_id,file_id,size,updated_at FROM pool_objects WHERE key LIKE ? ESCAPE '\' ORDER BY key`,
		likePrefix(prefix))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PoolObject
	for rows.Next() {
		var p PoolObject
		var updated int64
		if err := rows.Scan(&p.Key, &p.AccountID, &p.FileID, &p.Size, &updated); err != nil {
			return nil, err
		}
		p.UpdatedAt = fromUnix(updated)
		out = append(out, p)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// OAuth states

// CreateOAuthState stores a state + PKCE verifier for a short-lived flow.
func (s *Store) CreateOAuthState(ctx context.Context, state, verifier, accountID string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO oauth_states(state,verifier,account_id,created_at) VALUES(?,?,?,?)`,
		state, verifier, accountID, now())
	return err
}

// ConsumeOAuthState returns and deletes a state. States older than 15 minutes
// are rejected.
func (s *Store) ConsumeOAuthState(ctx context.Context, state string) (verifier, accountID string, err error) {
	var created int64
	err = s.db.QueryRowContext(ctx, `SELECT verifier,account_id,created_at FROM oauth_states WHERE state=?`, state).
		Scan(&verifier, &accountID, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrNotFound
	}
	if err != nil {
		return "", "", err
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM oauth_states WHERE state=?`, state)
	if time.Since(fromUnix(created)) > 15*time.Minute {
		return "", "", ErrExpired
	}
	return verifier, accountID, nil
}

// PruneOAuthStates removes stale states.
func (s *Store) PruneOAuthStates(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM oauth_states WHERE created_at < ?`, time.Now().Add(-time.Hour).Unix())
	return err
}

// ---------------------------------------------------------------------------
// Helpers

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// ErrExpired is returned for stale OAuth states.
var ErrExpired = errors.New("expired")

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func likePrefix(prefix string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return replacer.Replace(prefix) + "%"
}

// String renders an account for logs without secrets.
func (a *Account) String() string {
	return fmt.Sprintf("%s <%s>", a.Name, a.Email)
}
