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
	AccessKey  string
	Secret     string
	Label      string
	Active     bool
	CreatedAt  time.Time
	LastUsedAt time.Time
}

// Event is one S3 request, used by the dashboard.
type Event struct {
	ID        int64
	TS        time.Time
	Op        string
	Bucket    string
	Key       string
	AccountID string
	Bytes     int64
	Status    int
	MS        int64
}

// Upload tracks an in-flight S3 multipart upload.
type Upload struct {
	ID          string
	Bucket      string
	Key         string
	AccountID   string
	ContentType string
	CreatedAt   time.Time
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
	_, err := s.db.Exec(schema)
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
		(id,name,email,picture,client_id,client_secret,refresh_token,access_token,token_expiry,root_id,needs_reauth,created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		a.ID, a.Name, a.Email, a.Picture, a.ClientID, cs, rt, at,
		a.TokenExpiry.Unix(), a.RootID, boolInt(a.NeedsReauth), a.CreatedAt.Unix())
	return err
}

const accountCols = `id,name,email,picture,client_id,client_secret,refresh_token,access_token,token_expiry,root_id,needs_reauth,created_at`

func (s *Store) scanAccount(row interface{ Scan(...any) error }) (*Account, error) {
	var a Account
	var secret, refresh, access string
	var expiry, created int64
	var reauth int
	err := row.Scan(&a.ID, &a.Name, &a.Email, &a.Picture, &a.ClientID, &secret, &refresh,
		&access, &expiry, &a.RootID, &reauth, &created)
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

// DeleteAccount removes an account and its buckets. Drive files are untouched.
func (s *Store) DeleteAccount(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM accounts WHERE id=?`, id)
	return err
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

// DeleteBucket removes a bucket mapping.
func (s *Store) DeleteBucket(ctx context.Context, name string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM buckets WHERE name=?`, name)
	return err
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
	_, err = s.db.ExecContext(ctx, `INSERT INTO access_keys(access_key,secret,label,active,created_at,last_used_at) VALUES(?,?,?,?,?,?)`,
		k.AccessKey, enc, k.Label, boolInt(k.Active), k.CreatedAt.Unix(), k.LastUsedAt.Unix())
	return err
}

// GetAccessKeySecret returns the decrypted secret for signature checks.
func (s *Store) GetAccessKeySecret(ctx context.Context, accessKey string) (string, bool, error) {
	var enc string
	var active int
	err := s.db.QueryRowContext(ctx, `SELECT secret,active FROM access_keys WHERE access_key=?`, accessKey).Scan(&enc, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, ErrNotFound
	}
	if err != nil {
		return "", false, err
	}
	secret, err := s.box.Open(enc)
	return secret, active != 0, err
}

// ListAccessKeys returns keys without their secrets.
func (s *Store) ListAccessKeys(ctx context.Context) ([]*AccessKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT access_key,label,active,created_at,last_used_at FROM access_keys ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AccessKey
	for rows.Next() {
		var k AccessKey
		var active, created, used int64
		if err := rows.Scan(&k.AccessKey, &k.Label, &active, &created, &used); err != nil {
			return nil, err
		}
		k.Active = active != 0
		k.CreatedAt = fromUnix(created)
		k.LastUsedAt = fromUnix(used)
		out = append(out, &k)
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
	_, err := s.db.ExecContext(ctx, `INSERT INTO events(ts,op,bucket,key,account_id,bytes,status,ms) VALUES(?,?,?,?,?,?,?,?)`,
		e.TS.Unix(), e.Op, e.Bucket, e.Key, e.AccountID, e.Bytes, e.Status, e.MS)
	return err
}

// RecentEvents returns the newest events.
func (s *Store) RecentEvents(ctx context.Context, limit int) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,ts,op,bucket,key,account_id,bytes,status,ms FROM events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Op, &e.Bucket, &e.Key, &e.AccountID, &e.Bytes, &e.Status, &e.MS); err != nil {
			return nil, err
		}
		e.TS = fromUnix(ts)
		out = append(out, e)
	}
	return out, rows.Err()
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
	_, err := s.db.ExecContext(ctx, `INSERT INTO uploads(id,bucket,key,account_id,content_type,created_at) VALUES(?,?,?,?,?,?)`,
		u.ID, u.Bucket, u.Key, u.AccountID, u.ContentType, u.CreatedAt.Unix())
	return err
}

// GetUpload returns an upload by id.
func (s *Store) GetUpload(ctx context.Context, id, bucket, key string) (*Upload, error) {
	var u Upload
	var created int64
	err := s.db.QueryRowContext(ctx, `SELECT id,bucket,key,account_id,content_type,created_at FROM uploads WHERE id=? AND bucket=? AND key=?`,
		id, bucket, key).Scan(&u.ID, &u.Bucket, &u.Key, &u.AccountID, &u.ContentType, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.CreatedAt = fromUnix(created)
	return &u, nil
}

// ListUploads returns in-flight uploads for a bucket ("" for all).
func (s *Store) ListUploads(ctx context.Context, bucket string) ([]*Upload, error) {
	q := `SELECT id,bucket,key,account_id,content_type,created_at FROM uploads`
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
		var u Upload
		var created int64
		if err := rows.Scan(&u.ID, &u.Bucket, &u.Key, &u.AccountID, &u.ContentType, &created); err != nil {
			return nil, err
		}
		u.CreatedAt = fromUnix(created)
		out = append(out, &u)
	}
	return out, rows.Err()
}

// DeleteUpload removes an upload record.
func (s *Store) DeleteUpload(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM uploads WHERE id=?`, id)
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

func likePrefix(prefix string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return replacer.Replace(prefix) + "%"
}

// String renders an account for logs without secrets.
func (a *Account) String() string {
	return fmt.Sprintf("%s <%s>", a.Name, a.Email)
}
