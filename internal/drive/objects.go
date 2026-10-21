package drive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"s3drive/internal/google"
	"s3drive/internal/store"
)

// PutResult is the outcome of an object write.
type PutResult struct {
	ETag      string
	Size      int64
	FileID    string
	AccountID string
	Modified  time.Time
}

// Put streams an object into Drive, creating the folder chain as needed.
func (s *Service) Put(ctx context.Context, bucketName, key, contentType string, r io.Reader) (*PutResult, error) {
	path, size, sum, err := s.spool(r)
	if err != nil {
		return nil, err
	}
	defer removeFile(path)
	return s.putFile(ctx, bucketName, key, contentType, path, size, sum)
}

func (s *Service) putFile(ctx context.Context, bucketName, key, contentType, path string, size int64, md5hex string) (*PutResult, error) {
	ref, err := s.Bucket(ctx, bucketName)
	if err != nil {
		return nil, err
	}
	dirs, name, err := splitKey(key)
	if err != nil {
		return nil, err
	}

	acct, folderID, err := s.writeTarget(ctx, ref, size)
	if err != nil {
		return nil, err
	}
	parent, err := s.ensureFolder(ctx, acct, folderID, dirs)
	if err != nil {
		return nil, err
	}

	existing, err := s.Google.FindChild(ctx, acct, parent, name, false)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if existing != nil && existing.IsFolder {
		return nil, newError("InvalidArgument", "a folder named %q already exists", name)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	existingID := ""
	if existing != nil {
		existingID = existing.ID
	}
	var previous *store.PoolObject
	if ref.Pool {
		if p, err := s.Store.GetPoolObject(ctx, key); err == nil {
			previous = p
		}
	}
	uploaded, err := s.Google.Upload(ctx, acct, existingID, parent, name, contentType, f, size)
	if err != nil {
		return nil, err
	}

	if ref.Pool {
		_ = s.Store.PutPoolObject(ctx, store.PoolObject{
			Key: key, AccountID: acct.ID, FileID: uploaded.ID, Size: size,
		})
		// The key moved to another file/account; drop the stale copy so it
		// does not consume quota or reappear when the index is rebuilt.
		if previous != nil && previous.FileID != "" && previous.FileID != uploaded.ID {
			if oldAcct, err := s.Store.GetAccount(ctx, previous.AccountID); err == nil {
				if err := s.Google.Delete(ctx, oldAcct, previous.FileID); err != nil && !isGoogleNotFound(err) {
					s.Log.Warn("remove stale pool copy", "key", key, "account", oldAcct.Email, "err", err)
				}
			}
		}
	}

	return &PutResult{
		ETag: md5hex, Size: size, FileID: uploaded.ID, AccountID: acct.ID,
		Modified: uploaded.Modified,
	}, nil
}

// PutFile uploads a file already staged on disk.
func (s *Service) PutFile(ctx context.Context, bucketName, key, contentType, path string, size int64, md5hex string) (*PutResult, error) {
	return s.putFile(ctx, bucketName, key, contentType, path, size, md5hex)
}

// PutVerified is Put with an expected MD5 (Content-MD5 validation).
func (s *Service) PutVerified(ctx context.Context, bucketName, key, contentType string, r io.Reader, expectedMD5 string) (*PutResult, error) {
	path, size, sum, err := s.spool(r)
	if err != nil {
		return nil, err
	}
	defer removeFile(path)
	if expectedMD5 != "" && !strings.EqualFold(sum, expectedMD5) {
		return nil, newError("BadDigest", "the Content-MD5 you specified did not match what we received")
	}
	return s.putFile(ctx, bucketName, key, contentType, path, size, sum)
}

// writeTarget returns the account and bucket folder used for a write.
func (s *Service) writeTarget(ctx context.Context, ref *BucketRef, need int64) (*store.Account, string, error) {
	if !ref.Pool {
		if ref.Account == nil {
			return nil, "", newError("NoSuchBucket", "bucket %q has no account", ref.Name)
		}
		return ref.Account, ref.FolderID, nil
	}
	acct, err := s.pickAccount(ctx, "", need)
	if err != nil {
		return nil, "", err
	}
	folderID, err := s.ensurePoolFolder(ctx, acct)
	if err != nil {
		return nil, "", err
	}
	return acct, folderID, nil
}

func (s *Service) ensurePoolFolder(ctx context.Context, acct *store.Account) (string, error) {
	root, err := s.rootID(ctx, acct)
	if err != nil {
		return "", err
	}
	return s.ensureFolder(ctx, acct, root, []string{s.poolName(ctx)})
}

// ObjectReader is an open object stream.
type ObjectReader struct {
	Object       Object
	Account      *store.Account
	Body         io.ReadCloser
	ContentRange string
	StatusCode   int
}

// Stat resolves an object without opening its content stream.
func (s *Service) Stat(ctx context.Context, bucketName, key string) (*Object, *store.Account, error) {
	acct, f, err := s.locate(ctx, bucketName, key)
	if err != nil {
		return nil, nil, err
	}
	o := objectFromFile(key, acct, f)
	return &o, acct, nil
}

// Get opens an object. rangeHeader is passed through to Drive (bytes=...).
func (s *Service) Get(ctx context.Context, bucketName, key, rangeHeader string) (*ObjectReader, error) {
	acct, f, err := s.locate(ctx, bucketName, key)
	if err != nil {
		return nil, err
	}
	o := objectFromFile(key, acct, f)
	resp, err := s.Google.Download(ctx, acct, f.ID, rangeHeader)
	if err != nil {
		return nil, err
	}
	obj := &ObjectReader{Object: o, Account: acct, Body: resp.Body, StatusCode: resp.StatusCode}
	obj.ContentRange = resp.Header.Get("Content-Range")
	if len := resp.ContentLength; len >= 0 {
		obj.Object.Size = len
	}
	return obj, nil
}

// locate finds the account and Drive file for a key.
func (s *Service) locate(ctx context.Context, bucketName, key string) (*store.Account, *google.File, error) {
	if err := ValidateKey(key); err != nil {
		return nil, nil, err
	}
	ref, err := s.Bucket(ctx, bucketName)
	if err != nil {
		return nil, nil, err
	}
	dirs, name, err := splitKey(key)
	if err != nil {
		return nil, nil, err
	}

	if !ref.Pool {
		parent, err := s.findFolder(ctx, ref.Account, ref.FolderID, dirs)
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil, newError("NoSuchKey", "object %q does not exist", key)
		}
		if err != nil {
			return nil, nil, err
		}
		f, err := s.Google.FindChild(ctx, ref.Account, parent, name, false)
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil, newError("NoSuchKey", "object %q does not exist", key)
		}
		if err != nil {
			return nil, nil, err
		}
		return ref.Account, f, nil
	}

	// Pool: consult the index first.
	if p, err := s.Store.GetPoolObject(ctx, key); err == nil {
		if acct, err := s.Store.GetAccount(ctx, p.AccountID); err == nil {
			if f, err := s.Google.GetFile(ctx, acct, p.FileID); err == nil {
				return acct, f, nil
			}
		}
		_ = s.Store.DeletePoolObject(ctx, key)
	}

	accounts, err := s.Store.ListAccounts(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, acct := range accounts {
		folderID, err := s.ensurePoolFolder(ctx, acct)
		if err != nil {
			continue
		}
		parent, err := s.findFolder(ctx, acct, folderID, dirs)
		if err != nil {
			continue
		}
		f, err := s.Google.FindChild(ctx, acct, parent, name, false)
		if err != nil {
			continue
		}
		_ = s.Store.PutPoolObject(ctx, store.PoolObject{Key: key, AccountID: acct.ID, FileID: f.ID, Size: f.Size})
		return acct, f, nil
	}
	return nil, nil, newError("NoSuchKey", "object %q does not exist", key)
}

// Delete removes an object.
func (s *Service) Delete(ctx context.Context, bucketName, key string) error {
	acct, f, err := s.locate(ctx, bucketName, key)
	if err != nil {
		return err
	}
	if f.IsFolder {
		return newError("InvalidArgument", "cannot delete folder %q as an object", key)
	}
	if err := s.Google.Delete(ctx, acct, f.ID); err != nil {
		return err
	}
	_ = s.Store.DeletePoolObject(ctx, key)
	return nil
}

// DeleteEmptyFolder removes a folder after its contents have been deleted.
// It refuses to touch a folder that still has entries.
func (s *Service) DeleteEmptyFolder(ctx context.Context, bucketName, prefix string) error {
	prefix = strings.TrimPrefix(prefix, "/")
	if prefix == "" || !strings.HasSuffix(prefix, "/") {
		return newError("InvalidArgument", "folder prefix must end with /")
	}
	key := strings.TrimSuffix(prefix, "/")
	dirs, name, err := splitKey(key)
	if err != nil {
		return err
	}
	ref, err := s.Bucket(ctx, bucketName)
	if err != nil {
		return err
	}
	res, err := s.List(ctx, bucketName, prefix, "", 1, "")
	if err != nil {
		return err
	}
	if len(res.Objects) > 0 || len(res.CommonPrefixes) > 0 {
		return newError("BucketNotEmpty", "folder %q is not empty", prefix)
	}

	if !ref.Pool {
		return s.deleteFolderIn(ctx, ref.Account, ref.FolderID, dirs, name)
	}
	accounts, err := s.Store.ListAccounts(ctx)
	if err != nil {
		return err
	}
	var firstErr error
	for _, acct := range accounts {
		root, err := s.rootID(ctx, acct)
		if err != nil {
			continue
		}
		poolFolder, err := s.findFolder(ctx, acct, root, []string{s.poolName(ctx)})
		if err != nil {
			continue
		}
		if err := s.deleteFolderIn(ctx, acct, poolFolder, dirs, name); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *Service) deleteFolderIn(ctx context.Context, acct *store.Account, base string, dirs []string, name string) error {
	segments := append(append([]string{}, dirs...), name)
	folderID, err := s.findFolder(ctx, acct, base, segments)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := s.Google.Delete(ctx, acct, folderID); err != nil && !isGoogleNotFound(err) {
		return err
	}
	_ = s.Store.ForgetFolder(ctx, acct.ID, folderID)
	return nil
}

// DeletePrefix removes every object under prefix (used by the UI).
func (s *Service) DeletePrefix(ctx context.Context, bucketName, prefix string) (int, error) {
	deleted := 0
	for {
		res, err := s.List(ctx, bucketName, prefix, "", 1000, "")
		if err != nil {
			return deleted, err
		}
		if len(res.Objects) == 0 {
			break
		}
		for _, o := range res.Objects {
			if err := s.Delete(ctx, bucketName, o.Key); err != nil {
				return deleted, err
			}
			deleted++
		}
		if !res.IsTruncated {
			break
		}
		// The list starts from the beginning each time; deleting shrinks it.
	}
	if strings.HasSuffix(prefix, "/") {
		if err := s.deleteEmptyTree(ctx, bucketName, prefix); err != nil {
			return deleted, err
		}
	}
	return deleted, nil
}

// deleteEmptyTree removes empty folders below prefix, deepest first, and then
// the folder at prefix itself.
func (s *Service) deleteEmptyTree(ctx context.Context, bucketName, prefix string) error {
	for {
		res, err := s.List(ctx, bucketName, prefix, "/", 1000, "")
		if err != nil {
			return err
		}
		if len(res.CommonPrefixes) == 0 {
			break
		}
		for _, p := range res.CommonPrefixes {
			if err := s.deleteEmptyTree(ctx, bucketName, p); err != nil {
				return err
			}
		}
	}
	return s.DeleteEmptyFolder(ctx, bucketName, prefix)
}

// Copy copies an object, server-side when both sides live in the same account.
func (s *Service) Copy(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string) (*PutResult, error) {
	srcAcct, srcFile, err := s.locate(ctx, srcBucket, srcKey)
	if err != nil {
		return nil, err
	}
	if err := ValidateKey(dstKey); err != nil {
		return nil, err
	}
	dstRef, err := s.Bucket(ctx, dstBucket)
	if err != nil {
		return nil, err
	}
	dirs, name, err := splitKey(dstKey)
	if err != nil {
		return nil, err
	}
	dstAcct, dstFolder, err := s.writeTarget(ctx, dstRef, srcFile.Size)
	if err != nil {
		return nil, err
	}
	parent, err := s.ensureFolder(ctx, dstAcct, dstFolder, dirs)
	if err != nil {
		return nil, err
	}
	existing, err := s.Google.FindChild(ctx, dstAcct, parent, name, false)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if srcAcct.ID == dstAcct.ID && existing != nil && existing.ID == srcFile.ID {
		// Copy onto itself: S3 allows this as a metadata replacement.
		return &PutResult{ETag: srcFile.MD5, Size: srcFile.Size, FileID: srcFile.ID, AccountID: srcAcct.ID, Modified: srcFile.Modified}, nil
	}
	if existing != nil && existing.IsFolder {
		return nil, newError("InvalidArgument", "a folder named %q already exists", name)
	}

	if srcAcct.ID == dstAcct.ID {
		if existing != nil {
			if err := s.Google.Delete(ctx, dstAcct, existing.ID); err != nil {
				return nil, err
			}
		}
		copied, err := s.Google.Copy(ctx, dstAcct, srcFile.ID, name, parent)
		if err != nil {
			return nil, err
		}
		if dstRef.Pool {
			_ = s.Store.PutPoolObject(ctx, store.PoolObject{Key: dstKey, AccountID: dstAcct.ID, FileID: copied.ID, Size: copied.Size})
		}
		return &PutResult{ETag: srcFile.MD5, Size: copied.Size, FileID: copied.ID, AccountID: dstAcct.ID, Modified: copied.Modified}, nil
	}

	// Cross-account: stream the source into the destination account.
	reader, err := s.Get(ctx, srcBucket, srcKey, "")
	if err != nil {
		return nil, err
	}
	defer reader.Body.Close()
	return s.Put(ctx, dstBucket, dstKey, srcFile.MimeType, reader.Body)
}

// CreateFolder creates an empty folder (UI convenience; S3 has no folders).
func (s *Service) CreateFolder(ctx context.Context, bucketName, key string) error {
	key = strings.TrimSuffix(key, "/")
	if key == "" {
		return newError("InvalidObjectName", "empty folder name")
	}
	dirs, name, err := splitKey(key)
	if err != nil {
		return err
	}
	ref, err := s.Bucket(ctx, bucketName)
	if err != nil {
		return err
	}
	acct, folderID, err := s.writeTarget(ctx, ref, 0)
	if err != nil {
		return err
	}
	parent, err := s.ensureFolder(ctx, acct, folderID, dirs)
	if err != nil {
		return err
	}
	if f, err := s.Google.FindChild(ctx, acct, parent, name, true); err == nil && f != nil {
		return newError("InvalidArgument", "folder %q already exists", key)
	}
	_, err = s.Google.CreateFolder(ctx, acct, name, parent)
	return err
}

// pickAccount chooses an account for writes. preferred wins when set;
// otherwise the account with the most free space is used.
func (s *Service) pickAccount(ctx context.Context, preferred string, need int64) (*store.Account, error) {
	accounts, err := s.Store.ListAccounts(ctx)
	if err != nil {
		return nil, err
	}
	if len(accounts) == 0 {
		return nil, newError("AccessDenied", "no Google account is connected")
	}
	if preferred != "" {
		for _, a := range accounts {
			if a.ID == preferred || a.Email == preferred || a.Name == preferred {
				return a, nil
			}
		}
		return nil, newError("InvalidArgument", "unknown account %q", preferred)
	}

	var best *store.Account
	var bestFree int64 = -1
	for _, a := range accounts {
		about, err := s.AccountQuota(ctx, a, false)
		if err != nil {
			continue
		}
		free := int64(1 << 60) // unlimited / unknown
		if about.Limit > 0 {
			free = about.Limit - about.Usage
		}
		if need > 0 && about.Limit > 0 && free < need {
			continue
		}
		if free > bestFree {
			best, bestFree = a, free
		}
	}
	if best == nil {
		if need > 0 {
			return nil, newError("AccessDenied", "no connected account has enough free space")
		}
		return accounts[0], nil
	}
	return best, nil
}

// AccountQuota returns cached storage quota information.
func (s *Service) AccountQuota(ctx context.Context, acct *store.Account, force bool) (*google.About, error) {
	s.mu.Lock()
	entry, ok := s.quotas[acct.ID]
	s.mu.Unlock()
	if ok && !force && time.Since(entry.at) < 2*time.Minute {
		return entry.about, nil
	}
	about, err := s.Google.About(ctx, acct)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.quotas[acct.ID] = quotaEntry{about: about, at: time.Now()}
	s.mu.Unlock()
	return about, nil
}

// TotalStorage aggregates quota across accounts (accounts without a limit
// are reported as unlimited when at least one exists).
func (s *Service) TotalStorage(ctx context.Context) (used, limit int64, unlimited bool, err error) {
	accounts, err := s.Store.ListAccounts(ctx)
	if err != nil {
		return 0, 0, false, err
	}
	for _, a := range accounts {
		about, qerr := s.AccountQuota(ctx, a, false)
		if qerr != nil {
			continue
		}
		used += about.Usage
		if about.Limit == 0 {
			unlimited = true
		} else {
			limit += about.Limit
		}
	}
	return used, limit, unlimited, nil
}

// PresignTarget resolves the account a presigned request should use.
func (s *Service) PresignTarget(ctx context.Context, bucketName string) (*store.Account, error) {
	ref, err := s.Bucket(ctx, bucketName)
	if err != nil {
		return nil, err
	}
	if ref.Pool {
		return s.pickAccount(ctx, "", 0)
	}
	return ref.Account, nil
}

// FormatBytes is a small helper shared by templates.
func FormatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// IsNotFound reports whether err is an S3 NoSuchKey/NoSuchBucket error.
func IsNotFound(err error) bool {
	var de *Error
	if errors.As(err, &de) {
		return de.Code == "NoSuchKey" || de.Code == "NoSuchBucket"
	}
	return false
}

// HTTPStatusOf maps a service error to an HTTP status.
func HTTPStatusOf(err error) int {
	var de *Error
	if errors.As(err, &de) {
		return de.Status
	}
	if errors.Is(err, context.Canceled) {
		return 499
	}
	return http.StatusInternalServerError
}
