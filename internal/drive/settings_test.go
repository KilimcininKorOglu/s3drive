package drive

import (
	"context"
	"path/filepath"
	"testing"

	"s3drive/internal/secure"
	"s3drive/internal/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	box, err := secure.New(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "test.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// Unset settings use the documented defaults; stored values override them,
// "0" disables pooling and the public URL loses its trailing slash.
func TestLoadSettings(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	svc := &Service{Store: st, PublicURL: "http://localhost:8080"}

	got, err := svc.LoadSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := Settings{Region: "us-east-1", PoolName: "pool", PoolEnabled: true, PublicURL: "http://localhost:8080", SiteName: "s3drive", Namespace: "s3drive"}
	if got != want {
		t.Fatalf("defaults = %+v, want %+v", got, want)
	}

	for k, v := range map[string]string{
		SettingRegion: "eu-west-1", SettingPoolName: "shared", SettingPoolEnabled: "0",
		SettingPublicURL: "https://s3.example.com/", SettingCORS: "https://app.example.com",
		SettingSiteName: "Files", SettingNamespace: "ns",
	} {
		if err := st.SetSetting(ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}
	got, err = svc.LoadSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want = Settings{Region: "eu-west-1", PoolName: "shared", PoolEnabled: false, PublicURL: "https://s3.example.com",
		CORSOrigins: "https://app.example.com", SiteName: "Files", Namespace: "ns"}
	if got != want {
		t.Fatalf("stored = %+v, want %+v", got, want)
	}
}
