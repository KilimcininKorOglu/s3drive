// Package google implements the small slice of the Google Drive v3 API that
// s3drive needs, plus the OAuth desktop/web authorization flow.
package google

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"s3drive/internal/pctenc"
	"s3drive/internal/store"
)

const (
	driveAPI  = "https://www.googleapis.com/drive/v3"
	uploadAPI = "https://www.googleapis.com/upload/drive/v3"
	tokenURL  = "https://oauth2.googleapis.com/token" // #nosec G101 -- public OAuth endpoint URL
	authURL   = "https://accounts.google.com/o/oauth2/v2/auth"

	// ScopeDrive grants full access to the account's Drive. s3drive needs it
	// to create buckets (folders) anywhere and to serve any object the user
	// exposes.
	ScopeDrive = "https://www.googleapis.com/auth/drive"

	fileFields = "id,name,mimeType,size,modifiedTime,md5Checksum,parents,appProperties"
)

// APIError is a non-2xx response from Google.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("google api %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("google api %d", e.Status)
}

// ErrReauth means the refresh token is no longer valid.
var ErrReauth = errors.New("google account needs to be reconnected")

// Client talks to Google on behalf of connected accounts and keeps access
// tokens fresh.
type Client struct {
	Store *store.Store
	HTTP  *http.Client

	mu     sync.Mutex
	tokens map[string]*tokenState
}

type tokenState struct {
	mu        sync.Mutex
	access    string
	expiresAt time.Time
}

// NewClient builds a Drive client.
func NewClient(st *store.Store) *Client {
	return &Client{
		Store: st,
		HTTP: &http.Client{
			Timeout: 0,
			Transport: &http.Transport{
				Proxy:               http.ProxyFromEnvironment,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		tokens: make(map[string]*tokenState),
	}
}

func (c *Client) state(accountID string) *tokenState {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, ok := c.tokens[accountID]
	if !ok {
		st = &tokenState{}
		c.tokens[accountID] = st
	}
	return st
}

// AccessToken returns a valid bearer token, refreshing it when needed.
func (c *Client) AccessToken(ctx context.Context, acct *store.Account) (string, error) {
	st := c.state(acct.ID)
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.access != "" && time.Until(st.expiresAt) > 2*time.Minute {
		return st.access, nil
	}
	if acct.AccessToken != "" && time.Until(acct.TokenExpiry) > 2*time.Minute {
		st.access, st.expiresAt = acct.AccessToken, acct.TokenExpiry
		return st.access, nil
	}
	return c.refreshLocked(ctx, acct, st)
}

// ForceRefresh discards the cached token and fetches a new one.
func (c *Client) ForceRefresh(ctx context.Context, acct *store.Account) (string, error) {
	st := c.state(acct.ID)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.access = ""
	return c.refreshLocked(ctx, acct, st)
}

// postRefresh sends the refresh_token grant with the account's own OAuth
// client, or the global one, and returns the status and body (max 1 MiB).
func (c *Client) postRefresh(ctx context.Context, acct *store.Account) (int, []byte, error) {
	clientID, clientSecret := acct.ClientID, acct.ClientSecret
	if clientID == "" || clientSecret == "" {
		var err error
		if clientID, clientSecret, err = c.ClientCredentials(ctx); err != nil {
			return 0, nil, err
		}
	}
	form := fmt.Sprintf("client_id=%s&client_secret=%s&refresh_token=%s&grant_type=refresh_token",
		urlEncode(clientID), urlEncode(clientSecret), urlEncode(acct.RefreshToken))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }() // body fully read below
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, nil, fmt.Errorf("read token response: %w", err)
	}
	return resp.StatusCode, body, nil
}

// refreshError maps a failed refresh. A revoked grant marks the account for
// re-authorization and returns ErrReauth.
func (c *Client) refreshError(ctx context.Context, accountID string, status int, body []byte) error {
	var oe struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &oe) // a non-JSON body leaves oe empty and is reported verbatim below
	if oe.Error != "invalid_grant" && oe.Error != "unauthorized_client" {
		return fmt.Errorf("token refresh failed (%d): %s", status, strings.TrimSpace(string(body)))
	}
	reauthErr := fmt.Errorf("%w: %s", ErrReauth, oe.ErrorDescription)
	if err := c.Store.MarkAccountReauth(ctx, accountID); err != nil {
		return errors.Join(reauthErr, fmt.Errorf("mark account for re-auth: %w", err))
	}
	return reauthErr
}

func (c *Client) refreshLocked(ctx context.Context, acct *store.Account, st *tokenState) (string, error) {
	if acct.RefreshToken == "" {
		return "", ErrReauth
	}
	status, body, err := c.postRefresh(ctx, acct)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", c.refreshError(ctx, acct.ID, status, body)
	}
	var tok Token
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", err
	}
	if tok.AccessToken == "" {
		return "", errors.New("token refresh returned no access token")
	}
	expiry := tok.Expiry
	if expiry.IsZero() {
		expiry = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	}
	st.access, st.expiresAt = tok.AccessToken, expiry
	if err := c.Store.UpdateAccountTokens(ctx, acct.ID, tok.AccessToken, expiry); err != nil {
		return "", err
	}
	acct.AccessToken, acct.TokenExpiry, acct.NeedsReauth = tok.AccessToken, expiry, false
	return tok.AccessToken, nil
}

// do runs an authenticated request and one forced token refresh. Retries are
// deliberately limited to safe/idempotent methods: replaying a Drive POST
// after a timeout can otherwise create a second folder or file.
func (c *Client) do(ctx context.Context, acct *store.Account, method, url string, body io.Reader, headers map[string]string) (*http.Response, error) {
	var bodyBytes []byte
	if body != nil {
		b, err := io.ReadAll(body)
		if err != nil {
			return nil, err
		}
		bodyBytes = b
	}
	rq := &apiRequest{
		acct: acct, method: method, url: url, body: bodyBytes, headers: headers,
		// Only idempotent methods are retried after a transport error, 429 or
		// 5xx; POST/PATCH must never be sent twice.
		retryable: method == http.MethodGet || method == http.MethodHead || method == http.MethodDelete,
	}
	var lastErr error
	for attempt := range 6 {
		o := c.attempt(ctx, rq, attempt)
		if !o.retry {
			return o.resp, o.err
		}
		if o.err != nil {
			lastErr = o.err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("request failed")
	}
	return nil, lastErr
}

// apiRequest is one Drive API call, replayable across attempts.
type apiRequest struct {
	acct      *store.Account
	method    string
	url       string
	body      []byte
	headers   map[string]string
	retryable bool
	refreshed bool // the token was already force-refreshed after a 401
}

// outcome is the result of one attempt. With retry set, err is the error to
// report if no attempt is left (nil after a token refresh); any backoff has
// already been applied.
type outcome struct {
	resp  *http.Response
	err   error
	retry bool
}

func (c *Client) attempt(ctx context.Context, rq *apiRequest, n int) outcome {
	token, err := c.AccessToken(ctx, rq.acct)
	if err != nil {
		return outcome{err: err}
	}
	var reader io.Reader
	if rq.body != nil {
		reader = bytes.NewReader(rq.body)
	}
	req, err := http.NewRequestWithContext(ctx, rq.method, rq.url, reader)
	if err != nil {
		return outcome{err: err}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	for k, v := range rq.headers {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return transportFailure(ctx, rq, err, n)
	}
	return c.classify(ctx, rq, resp, n)
}

func transportFailure(ctx context.Context, rq *apiRequest, err error, n int) outcome {
	if ctx.Err() != nil {
		return outcome{err: ctx.Err()}
	}
	if !rq.retryable {
		return outcome{err: err}
	}
	sleepBackoff(ctx, n)
	return outcome{err: err, retry: true}
}

// classify maps a response: one forced token refresh after a 401, backoff
// on 429/5xx for retryable methods, and API errors for other 4xx.
func (c *Client) classify(ctx context.Context, rq *apiRequest, resp *http.Response, n int) outcome {
	if resp.StatusCode == http.StatusUnauthorized && !rq.refreshed {
		_ = resp.Body.Close() // discarded 401 response, retried after refresh
		rq.refreshed = true
		if _, err := c.ForceRefresh(ctx, rq.acct); err != nil {
			return outcome{err: err}
		}
		return outcome{retry: true}
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		apiErr := readAPIError(resp)
		if rq.retryable && n < 5 {
			sleepBackoff(ctx, n)
			return outcome{err: apiErr, retry: true}
		}
		return outcome{err: apiErr}
	}
	if resp.StatusCode >= 400 {
		return outcome{err: readAPIError(resp)}
	}
	return outcome{resp: resp}
}

func readAPIError(resp *http.Response) error {
	defer func() { _ = resp.Body.Close() }() // error body, already consumed
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var payload struct {
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Errors  []struct {
				Reason string `json:"reason"`
			} `json:"errors"`
		} `json:"error"`
	}
	apiErr := &APIError{Status: resp.StatusCode, Message: strings.TrimSpace(string(body))}
	if json.Unmarshal(body, &payload) == nil && payload.Error.Message != "" {
		apiErr.Message = payload.Error.Message
		if len(payload.Error.Errors) > 0 {
			apiErr.Code = payload.Error.Errors[0].Reason
		}
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return ErrReauth
	}
	return apiErr
}

func sleepBackoff(ctx context.Context, attempt int) {
	d := min(time.Duration(1<<uint(attempt))*250*time.Millisecond, 8*time.Second)
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// RawFile is the Drive file resource subset used by s3drive.
type RawFile struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	MimeType      string            `json:"mimeType"`
	Size          string            `json:"size"`
	ModifiedTime  string            `json:"modifiedTime"`
	MD5           string            `json:"md5Checksum"`
	Parents       []string          `json:"parents"`
	AppProperties map[string]string `json:"appProperties"`
}

// File is a normalized Drive file.
type File struct {
	ID            string
	Name          string
	MimeType      string
	Size          int64
	Modified      time.Time
	MD5           string
	Parents       []string
	AppProperties map[string]string
	IsFolder      bool
}

// FolderMime is the Drive folder MIME type.
const FolderMime = "application/vnd.google-apps.folder"

func normalizeFile(r RawFile) File {
	size, _ := strconv.ParseInt(r.Size, 10, 64)
	mod, _ := time.Parse(time.RFC3339Nano, r.ModifiedTime)
	return File{
		ID:            r.ID,
		Name:          r.Name,
		MimeType:      r.MimeType,
		Size:          size,
		Modified:      mod,
		MD5:           r.MD5,
		Parents:       r.Parents,
		AppProperties: r.AppProperties,
		IsFolder:      r.MimeType == FolderMime,
	}
}

// RootFolderID resolves the "My Drive" folder id.
func (c *Client) RootFolderID(ctx context.Context, acct *store.Account) (string, error) {
	resp, err := c.do(ctx, acct, http.MethodGet, driveAPI+"/files/root?fields=id", nil, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }() // read-only response body
	var f RawFile
	if err := json.NewDecoder(resp.Body).Decode(&f); err != nil {
		return "", err
	}
	return f.ID, nil
}

// About returns the account identity and storage quota.
func (c *Client) About(ctx context.Context, acct *store.Account) (*About, error) {
	u := driveAPI + "/about?fields=user(displayName,emailAddress,photoLink),storageQuota(limit,usage,usageInDrive)"
	resp, err := c.do(ctx, acct, http.MethodGet, u, nil, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }() // read-only response body
	var raw struct {
		User struct {
			DisplayName  string `json:"displayName"`
			EmailAddress string `json:"emailAddress"`
			PhotoLink    string `json:"photoLink"`
		} `json:"user"`
		StorageQuota struct {
			Limit        string `json:"limit"`
			Usage        string `json:"usage"`
			UsageInDrive string `json:"usageInDrive"`
		} `json:"storageQuota"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	limit, _ := strconv.ParseInt(raw.StorageQuota.Limit, 10, 64)
	usage, _ := strconv.ParseInt(raw.StorageQuota.Usage, 10, 64)
	inDrive, _ := strconv.ParseInt(raw.StorageQuota.UsageInDrive, 10, 64)
	return &About{
		Name:         raw.User.DisplayName,
		Email:        raw.User.EmailAddress,
		Picture:      raw.User.PhotoLink,
		Limit:        limit,
		Usage:        usage,
		UsageInDrive: inDrive,
	}, nil
}

// About is identity plus quota.
type About struct {
	Name         string
	Email        string
	Picture      string
	Limit        int64
	Usage        int64
	UsageInDrive int64
}

// ListChildren lists one page of a folder's direct children.
func (c *Client) ListChildren(ctx context.Context, acct *store.Account, parentID, pageToken string) ([]File, string, error) {
	q := fmt.Sprintf("'%s' in parents and trashed = false", qEscape(parentID))
	u := fmt.Sprintf("%s/files?q=%s&fields=nextPageToken,files(%s)&pageSize=1000&orderBy=name",
		driveAPI, urlEncode(q), fileFields)
	if pageToken != "" {
		u += "&pageToken=" + urlEncode(pageToken)
	}
	resp, err := c.do(ctx, acct, http.MethodGet, u, nil, nil)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }() // read-only response body
	var payload struct {
		NextPageToken string    `json:"nextPageToken"`
		Files         []RawFile `json:"files"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, "", err
	}
	out := make([]File, 0, len(payload.Files))
	for _, f := range payload.Files {
		out = append(out, normalizeFile(f))
	}
	return out, payload.NextPageToken, nil
}

// FindChild looks up a file or folder by exact name inside a parent folder.
func (c *Client) FindChild(ctx context.Context, acct *store.Account, parentID, name string, folder bool) (*File, error) {
	q := fmt.Sprintf("name = '%s' and '%s' in parents and trashed = false", qEscape(name), qEscape(parentID))
	if folder {
		q += fmt.Sprintf(" and mimeType = '%s'", FolderMime)
	}
	u := fmt.Sprintf("%s/files?q=%s&fields=files(%s)&pageSize=10", driveAPI, urlEncode(q), fileFields)
	resp, err := c.do(ctx, acct, http.MethodGet, u, nil, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }() // read-only response body
	var payload struct {
		Files []RawFile `json:"files"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	if len(payload.Files) == 0 {
		return nil, store.ErrNotFound
	}
	f := normalizeFile(payload.Files[0])
	return &f, nil
}

// GetFile fetches metadata for one file id.
func (c *Client) GetFile(ctx context.Context, acct *store.Account, id string) (*File, error) {
	u := fmt.Sprintf("%s/files/%s?fields=%s", driveAPI, urlEncode(id), fileFields)
	resp, err := c.do(ctx, acct, http.MethodGet, u, nil, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }() // read-only response body
	var raw RawFile
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	f := normalizeFile(raw)
	return &f, nil
}

// CreateFolder creates a folder under parentID.
func (c *Client) CreateFolder(ctx context.Context, acct *store.Account, name, parentID string) (*File, error) {
	return c.CreateFolderWithProps(ctx, acct, name, parentID, nil)
}

// CreateFolderWithProps creates a folder and attaches private appProperties.
// s3drive uses this as an ownership marker so it never adopts a pre-existing
// user folder with the same name.
func (c *Client) CreateFolderWithProps(ctx context.Context, acct *store.Account, name, parentID string, props map[string]string) (*File, error) {
	meta := map[string]any{
		"name":     name,
		"mimeType": FolderMime,
		"parents":  []string{parentID},
	}
	if len(props) > 0 {
		meta["appProperties"] = props
	}
	body, _ := json.Marshal(meta)
	u := fmt.Sprintf("%s/files?fields=%s", driveAPI, fileFields)
	resp, err := c.do(ctx, acct, http.MethodPost, u, strings.NewReader(string(body)), map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }() // read-only response body
	var raw RawFile
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	f := normalizeFile(raw)
	return &f, nil
}

// Rename changes a Drive file or folder name.
func (c *Client) Rename(ctx context.Context, acct *store.Account, id, name string) (*File, error) {
	body, _ := json.Marshal(map[string]any{"name": name})
	u := fmt.Sprintf("%s/files/%s?fields=%s", driveAPI, urlEncode(id), fileFields)
	resp, err := c.do(ctx, acct, http.MethodPatch, u, strings.NewReader(string(body)), map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }() // read-only response body
	var raw RawFile
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	f := normalizeFile(raw)
	return &f, nil
}

// Move reparents a file or folder without copying its content.
func (c *Client) Move(ctx context.Context, acct *store.Account, id, newParent string) (*File, error) {
	old, err := c.GetFile(ctx, acct, id)
	if err != nil {
		return nil, err
	}
	remove := ""
	for _, p := range old.Parents {
		if p != newParent {
			remove = p
			break
		}
	}
	if remove == "" {
		return old, nil
	}
	u := fmt.Sprintf("%s/files/%s?addParents=%s&removeParents=%s&fields=%s",
		driveAPI, urlEncode(id), urlEncode(newParent), urlEncode(remove), fileFields)
	resp, err := c.do(ctx, acct, http.MethodPatch, u, nil, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }() // read-only response body
	var raw RawFile
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	f := normalizeFile(raw)
	return &f, nil
}

// SetAppProperties merges private appProperties onto a file/folder.
func (c *Client) SetAppProperties(ctx context.Context, acct *store.Account, id string, props map[string]string) (*File, error) {
	body, _ := json.Marshal(map[string]any{"appProperties": props})
	u := fmt.Sprintf("%s/files/%s?fields=%s", driveAPI, urlEncode(id), fileFields)
	resp, err := c.do(ctx, acct, http.MethodPatch, u, strings.NewReader(string(body)), map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }() // read-only response body
	var raw RawFile
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	f := normalizeFile(raw)
	return &f, nil
}

// Delete permanently removes a file or folder.
func (c *Client) Delete(ctx context.Context, acct *store.Account, id string) error {
	resp, err := c.do(ctx, acct, http.MethodDelete, driveAPI+"/files/"+urlEncode(id), nil, nil)
	if err != nil {
		return err
	}
	_ = resp.Body.Close() // status already read, body not needed
	return nil
}

// Copy duplicates a file server-side.
func (c *Client) Copy(ctx context.Context, acct *store.Account, id, name, parentID string) (*File, error) {
	body, _ := json.Marshal(map[string]any{"name": name, "parents": []string{parentID}})
	u := fmt.Sprintf("%s/files/%s/copy?fields=%s", driveAPI, urlEncode(id), fileFields)
	resp, err := c.do(ctx, acct, http.MethodPost, u, strings.NewReader(string(body)), map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }() // read-only response body
	var raw RawFile
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	f := normalizeFile(raw)
	return &f, nil
}

// Download opens a media stream. rangeHeader may be "" or "bytes=...".
func (c *Client) Download(ctx context.Context, acct *store.Account, id, rangeHeader string) (*http.Response, error) {
	headers := map[string]string{}
	if rangeHeader != "" {
		headers["Range"] = rangeHeader
	}
	return c.do(ctx, acct, http.MethodGet, fmt.Sprintf("%s/files/%s?alt=media&supportsAllDrives=true", driveAPI, urlEncode(id)), nil, headers)
}

// Export downloads a native Google Doc/Sheet/Slide as a binary MIME type.
func (c *Client) Export(ctx context.Context, acct *store.Account, id, mime string) (*http.Response, error) {
	u := fmt.Sprintf("%s/files/%s/export?mimeType=%s&supportsAllDrives=true",
		driveAPI, urlEncode(id), urlEncode(mime))
	return c.do(ctx, acct, http.MethodGet, u, nil, nil)
}

// UploadResume identifies a persisted Drive resumable session. Identity must
// change whenever the source bytes or target file change.
type UploadResume struct {
	Bucket    string
	Key       string
	AccountID string
	Identity  string
	Size      int64
}

// Upload creates or replaces file content. When existingID is non-empty the
// file is updated in place, preserving its id (S3 overwrite semantics).
func (c *Client) Upload(ctx context.Context, acct *store.Account, existingID, parentID, name, mime string, r io.ReadSeeker, size int64, resume *UploadResume) (*File, error) {
	if mime == "" {
		mime = "application/octet-stream"
	}
	if size <= 4<<20 || resume == nil {
		return c.uploadMultipart(ctx, acct, existingID, parentID, name, mime, r, size)
	}
	return c.uploadResumable(ctx, acct, existingID, parentID, name, mime, r, size, resume)
}

func (c *Client) uploadMultipart(ctx context.Context, acct *store.Account, existingID, parentID, name, mime string, r io.ReadSeeker, size int64) (*File, error) {
	meta := map[string]any{"name": name}
	if existingID == "" {
		meta["parents"] = []string{parentID}
	}
	metaJSON, _ := json.Marshal(meta)

	boundary := "s3drive" + store.NewID()
	var body strings.Builder
	body.WriteString("--")
	body.WriteString(boundary)
	body.WriteString("\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n")
	body.Write(metaJSON)
	body.WriteString("\r\n--")
	body.WriteString(boundary)
	body.WriteString("\r\nContent-Type: ")
	body.WriteString(mime)
	body.WriteString("\r\n\r\n")
	prefix := body.String()
	var content []byte
	var err error
	if size > 0 {
		content = make([]byte, size)
		if _, err = io.ReadFull(r, content); err != nil {
			return nil, err
		}
	}
	suffix := "\r\n--" + boundary + "--\r\n"

	u := fmt.Sprintf("%s/files?uploadType=multipart&fields=%s", uploadAPI, fileFields)
	method := http.MethodPost
	if existingID != "" {
		method = http.MethodPatch
		u = fmt.Sprintf("%s/files/%s?uploadType=multipart&fields=%s", uploadAPI, urlEncode(existingID), fileFields)
	}
	// multipart/related body is assembled in memory (max 4 MiB).
	payload := append([]byte(prefix), content...)
	payload = append(payload, suffix...)
	resp, err := c.do(ctx, acct, method, u, strings.NewReader(string(payload)), map[string]string{
		"Content-Type": "multipart/related; boundary=" + boundary,
	})
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }() // read-only response body
	var raw RawFile
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	f := normalizeFile(raw)
	return &f, nil
}

const chunkSize = 32 << 20 // multiple of 256 KiB, as Drive requires

// resumeOrStart continues a stored session (or returns the file it already
// completed), else starts a new session at offset 0 and stores it so a
// restart can resume.
func (c *Client) resumeOrStart(ctx context.Context, acct *store.Account, resume *UploadResume, start func() (string, error)) (string, int64, *File, error) {
	sessionURL, offset, done, err := c.prepareResume(ctx, acct, resume)
	if err != nil || done != nil || sessionURL != "" {
		return sessionURL, offset, done, err
	}
	if sessionURL, err = start(); err != nil {
		return "", 0, nil, err
	}
	if err := c.saveResume(ctx, resume, sessionURL, 0); err != nil {
		return "", 0, nil, err
	}
	return sessionURL, 0, nil, nil
}

// seekToOffset positions r for the session. An offset outside the file, or
// a full offset without a completed file from the query, means the session
// is stale: it is dropped and usable is false.
func (c *Client) seekToOffset(ctx context.Context, r io.Seeker, offset, size int64, resume *UploadResume) (bool, error) {
	if offset < 0 || offset >= size {
		return false, c.dropResume(ctx, resume)
	}
	if _, err := r.Seek(offset, io.SeekStart); err != nil {
		return false, err
	}
	return true, nil
}

func (c *Client) uploadResumable(ctx context.Context, acct *store.Account, existingID, parentID, name, mime string, r io.ReadSeeker, size int64, resume *UploadResume) (*File, error) {
	start := func() (string, error) {
		return c.startResumable(ctx, acct, existingID, parentID, name, mime, size)
	}
	var lastErr error
	for range 3 {
		sessionURL, offset, done, err := c.resumeOrStart(ctx, acct, resume, start)
		if err != nil || done != nil {
			return done, err
		}
		usable, err := c.seekToOffset(ctx, r, offset, size, resume)
		if err != nil {
			return nil, err
		}
		if !usable {
			continue
		}
		file, retry, err := c.putResumableChunks(ctx, acct, sessionURL, r, size, offset, resume)
		if err == nil {
			c.forgetCompleted(ctx, resume)
			return file, nil
		}
		lastErr = err
		if !retry || ctx.Err() != nil {
			return nil, err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("upload failed after retries")
	}
	return nil, lastErr
}

// prepareResume looks up a persisted session and asks Drive how many bytes it
// has committed. It returns a completed file when the previous attempt actually
// finished before the process stopped.
// sessionMatches reports whether a stored session belongs to this exact
// upload (same account, content identity and size).
func sessionMatches(d *store.DriveSession, resume *UploadResume) bool {
	return d.SessionURL != "" && d.AccountID == resume.AccountID &&
		d.Identity == resume.Identity && d.Size == resume.Size
}

func (c *Client) prepareResume(ctx context.Context, acct *store.Account, resume *UploadResume) (string, int64, *File, error) {
	if resume == nil {
		return "", 0, nil, nil
	}
	d, err := c.Store.GetDriveSession(ctx, resume.Bucket, resume.Key)
	if errors.Is(err, store.ErrNotFound) {
		return "", 0, nil, nil
	}
	if err != nil {
		return "", 0, nil, err
	}
	if !sessionMatches(d, resume) {
		return "", 0, nil, c.dropResume(ctx, resume)
	}
	offset, file, err := c.queryResumable(ctx, acct, d.SessionURL, resume.Size)
	if errors.Is(err, errResumeGone) {
		return "", 0, nil, c.dropResume(ctx, resume)
	}
	if err != nil {
		return "", 0, nil, err
	}
	if file != nil {
		c.forgetCompleted(ctx, resume)
		return "", 0, file, nil
	}
	return d.SessionURL, offset, nil, nil
}

var errResumeGone = errors.New("resumable session expired")

// queryResumable asks Drive for the committed byte count of a resumable
// session. Drive answers 308 with a Range header, or 200 with the file when
// the upload already completed.
func (c *Client) queryResumable(ctx context.Context, acct *store.Account, sessionURL string, size int64) (int64, *File, error) {
	// The status query has an empty body and changes nothing on Drive, so it
	// is safe to repeat.
	for attempt := range 6 {
		resp, transport, err := c.statusQuery(ctx, acct, sessionURL, size)
		if err != nil && (!transport || ctx.Err() != nil) {
			return 0, nil, cmp.Or(ctx.Err(), err)
		}
		if err != nil {
			sleepBackoff(ctx, attempt)
			continue
		}
		q := c.readQueryStatus(ctx, acct, resp, attempt)
		if !q.retry {
			return q.offset, q.file, q.err
		}
	}
	return 0, nil, errors.New("could not query resumable upload status")
}

// statusQuery sends the "bytes */size" probe. transport reports that err
// came from the HTTP round trip rather than from building the request.
func (c *Client) statusQuery(ctx context.Context, acct *store.Account, sessionURL string, size int64) (*http.Response, bool, error) {
	token, err := c.AccessToken(ctx, acct)
	if err != nil {
		return nil, false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, sessionURL, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Range", fmt.Sprintf("bytes */%d", size))
	resp, err := c.HTTP.Do(req)
	return resp, err != nil, err
}

type queryResult struct {
	offset int64
	file   *File
	err    error
	retry  bool
}

// readQueryStatus maps the probe response: 308 gives the next offset,
// 200/201 the completed file, 404/410 a gone session. A 401 refreshes the
// token and 429/5xx back off before asking for another try.
func (c *Client) readQueryStatus(ctx context.Context, acct *store.Account, resp *http.Response, attempt int) queryResult {
	switch code := resp.StatusCode; {
	case code == 308:
		_ = resp.Body.Close() // status already read, body not needed
		return queryResult{offset: parseRangeOffset(resp.Header.Get("Range"))}
	case code == http.StatusOK || code == http.StatusCreated:
		f, err := decodeFile(resp)
		return queryResult{file: f, err: err}
	case code == http.StatusUnauthorized:
		_ = resp.Body.Close() // status already read, body not needed
		if _, err := c.ForceRefresh(ctx, acct); err != nil {
			return queryResult{err: err}
		}
		return queryResult{retry: true}
	case code == http.StatusNotFound || code == http.StatusGone:
		_ = resp.Body.Close() // status already read, body not needed
		return queryResult{err: errResumeGone}
	case code == http.StatusTooManyRequests || code >= 500:
		_ = readAPIError(resp) // drains and closes; the query is retried
		sleepBackoff(ctx, attempt)
		return queryResult{retry: true}
	}
	return queryResult{err: readAPIError(resp)}
}

func decodeFile(resp *http.Response) (*File, error) {
	defer func() { _ = resp.Body.Close() }() // read-only response body
	var raw RawFile
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	f := normalizeFile(raw)
	return &f, nil
}

func parseRangeOffset(header string) int64 {
	header = strings.TrimSpace(header)
	header = strings.TrimPrefix(header, "bytes=")
	_, end, ok := strings.Cut(header, "-")
	if !ok {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(end), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n + 1
}

// dropResume deletes a stale resumable session so the next attempt starts a
// new one. A failure is returned: a kept stale session would be reused.
// forgetCompleted deletes the session of an upload that Drive has already
// stored. The caller must still record the new file (metadata, pool index),
// so a failure is logged instead of turning the stored upload into an error.
// A kept session carries the content hash in its identity and resolves to the
// same completed file if it is ever reused.
func (c *Client) forgetCompleted(ctx context.Context, resume *UploadResume) {
	if err := c.dropResume(ctx, resume); err != nil {
		slog.Warn("drop completed upload session", "bucket", resume.Bucket, "key", resume.Key, "err", err)
	}
}

func (c *Client) dropResume(ctx context.Context, resume *UploadResume) error {
	if err := c.Store.DeleteDriveSession(ctx, resume.Bucket, resume.Key); err != nil {
		return fmt.Errorf("drop stale upload session: %w", err)
	}
	return nil
}

func (c *Client) saveResume(ctx context.Context, resume *UploadResume, sessionURL string, offset int64) error {
	if resume == nil {
		return nil
	}
	return c.Store.PutDriveSession(ctx, store.DriveSession{
		Bucket: resume.Bucket, Key: resume.Key, AccountID: resume.AccountID,
		SessionURL: sessionURL, Identity: resume.Identity, Size: resume.Size, Offset: offset,
	})
}

func (c *Client) startResumable(ctx context.Context, acct *store.Account, existingID, parentID, name, mime string, size int64) (string, error) {
	meta := map[string]any{"name": name, "mimeType": mime}
	if existingID == "" {
		meta["parents"] = []string{parentID}
	}
	body, _ := json.Marshal(meta)
	u := fmt.Sprintf("%s/files?uploadType=resumable&fields=%s", uploadAPI, fileFields)
	method := http.MethodPost
	if existingID != "" {
		method = http.MethodPatch
		u = fmt.Sprintf("%s/files/%s?uploadType=resumable&fields=%s", uploadAPI, urlEncode(existingID), fileFields)
	}
	resp, err := c.do(ctx, acct, method, u, strings.NewReader(string(body)), map[string]string{
		"Content-Type":            "application/json; charset=UTF-8",
		"X-Upload-Content-Type":   mime,
		"X-Upload-Content-Length": strconv.FormatInt(size, 10),
	})
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }() // read-only response body
	session := resp.Header.Get("Location")
	if session == "" {
		return "", errors.New("drive did not return a resumable session URL")
	}
	return session, nil
}

func (c *Client) putResumableChunks(ctx context.Context, acct *store.Account, sessionURL string, r io.ReadSeeker, size int64, offset int64, resume *UploadResume) (*File, bool, error) {
	buf := make([]byte, chunkSize)
	for offset < size {
		chunk := buf[:min(int64(len(buf)), size-offset)]
		if _, err := io.ReadFull(r, chunk); err != nil {
			return nil, false, err
		}
		res := c.putChunk(ctx, acct, sessionURL, chunk, offset, size)
		if res.err != nil || res.file != nil {
			return res.file, res.restart, res.err
		}
		offset = res.next
		if _, err := r.Seek(offset, io.SeekStart); err != nil {
			return nil, false, err
		}
		if err := c.saveResume(ctx, resume, sessionURL, offset); err != nil {
			return nil, false, err
		}
	}
	return nil, true, errors.New("upload finished without a response")
}

// chunkResult is the outcome of sending one chunk: the next offset Drive
// expects, or the finished file, or an error. restart asks the caller to
// begin a new upload session.
type chunkResult struct {
	next    int64
	file    *File
	err     error
	restart bool
}

// putChunk sends one chunk, retrying transport errors, 429/5xx and one token
// refresh per 401 within six attempts. A chunk that never gets a final
// answer is an error; it must not fall through to the next chunk, because
// Drive would then receive bytes at the wrong offset.
func (c *Client) putChunk(ctx context.Context, acct *store.Account, sessionURL string, chunk []byte, offset, size int64) chunkResult {
	var lastErr error
	for attempt := range 6 {
		resp, transport, err := c.sendChunk(ctx, acct, sessionURL, chunk, offset, size)
		if err != nil && (!transport || ctx.Err() != nil) {
			return chunkResult{err: cmp.Or(ctx.Err(), err)}
		}
		if err != nil {
			lastErr = err
			sleepBackoff(ctx, attempt)
			continue
		}
		res, again := c.readChunkStatus(ctx, acct, resp, offset, int64(len(chunk)), attempt)
		if !again {
			return res
		}
		lastErr = cmp.Or(res.err, lastErr)
	}
	return chunkResult{err: cmp.Or(lastErr, errors.New("chunk upload was not accepted after six attempts")), restart: true}
}

func (c *Client) sendChunk(ctx context.Context, acct *store.Account, sessionURL string, chunk []byte, offset, size int64) (*http.Response, bool, error) {
	token, err := c.AccessToken(ctx, acct)
	if err != nil {
		return nil, false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, sessionURL, bytes.NewReader(chunk))
	if err != nil {
		return nil, false, err
	}
	n := int64(len(chunk))
	req.ContentLength = n
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", offset, offset+n-1, size))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := c.HTTP.Do(req)
	return resp, err != nil, err
}

// nextOffset is where the next chunk starts after a 308. Drive may store
// only part of a chunk, so its Range header wins when it moved past offset;
// without one the whole chunk counts as stored.
func nextOffset(rangeHeader string, offset, n int64) int64 {
	if committed := parseRangeOffset(rangeHeader); committed > offset {
		return committed
	}
	return offset + n
}

// readChunkStatus maps a chunk response. again asks for another attempt of
// the same chunk (after a token refresh or a 429/5xx backoff).
func (c *Client) readChunkStatus(ctx context.Context, acct *store.Account, resp *http.Response, offset, n int64, attempt int) (chunkResult, bool) {
	switch code := resp.StatusCode; {
	case code == 308:
		_ = resp.Body.Close() // status already read, body not needed
		return chunkResult{next: nextOffset(resp.Header.Get("Range"), offset, n)}, false
	case code == http.StatusOK || code == http.StatusCreated:
		f, err := decodeFile(resp)
		return chunkResult{file: f, err: err}, false
	case code == http.StatusUnauthorized:
		_ = resp.Body.Close() // status already read, body not needed
		_, err := c.ForceRefresh(ctx, acct)
		return chunkResult{err: err}, err == nil
	case code == http.StatusForbidden || code == http.StatusNotFound || code == http.StatusGone:
		return chunkResult{err: readAPIError(resp), restart: true}, false
	case code == http.StatusTooManyRequests || code >= 500:
		apiErr := readAPIError(resp)
		sleepBackoff(ctx, attempt)
		return chunkResult{err: apiErr}, true
	}
	return chunkResult{err: readAPIError(resp)}, false
}

// ---------------------------------------------------------------------------
// helpers

func qEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `'`, `\'`)
}

func urlEncode(s string) string {
	// net/url.QueryEscape uses '+' for spaces; Drive accepts %20 everywhere.
	return strings.ReplaceAll(queryEscape(s), "+", "%20")
}

func queryEscape(s string) string { return pctenc.Encode(s, false) }

// Token is an OAuth token response.
type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresIn    int       `json:"expires_in"`
	TokenType    string    `json:"token_type"`
	Scope        string    `json:"scope"`
	Expiry       time.Time `json:"-"`
}
