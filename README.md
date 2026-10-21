# s3drive

**Google Drive as S3-compatible object storage.** A single Go binary with an htmx admin console, bilingual UI (English/Türkçe), light/dark themes, and multi-account pooling.

[English](#english) · [Türkçe](#türkçe)

> s3drive is an independent project. It is not affiliated with or endorsed by Google. Drive is a consumer file service, not a block device or a true object store — read the [limitations](#limitations) before trusting it with production data.

---

## English

### What it does

- **S3 API** on `:9000` (path-style): buckets, `ListObjectsV2` with prefix/delimiter/pagination, Put/Get/Head/Delete/Copy, Range and conditional GET, multipart uploads, presigned URLs, `DeleteObjects`, SigV4 header and query authentication.
- **Web console** on `:8080`: dashboard and quota, file browser/upload/download, bucket management, account connections, S3 access keys, OAuth settings.
- **Google Drive backend**: each bucket is a Drive folder under My Drive. `/` in an object key becomes a nested folder.
- **Multiple Google accounts**: pin a bucket to one account, and/or use the virtual **pool** bucket that merges every connected account. Pool uploads go to the account with the most free space; object→account mappings are kept in SQLite.
- **Secure by default**: encrypted refresh tokens (AES-256-GCM), S3 credentials encrypted at rest, optional console password, CSRF protection, signed session cookies, no external service dependencies.
- **Single binary + Docker**: HTML/CSS/JS and htmx are embedded with `go:embed`. SQLite is cgo-free (`modernc.org/sqlite`).

### How it works

```
S3 client ──SigV4──▶ :9000 ──▶ drive service ──▶ Google Drive API
Browser  ──cookie─▶ :8080 ──▶ drive service ──▶ Google Drive API
                               │
                               └──▶ SQLite (accounts, buckets, keys,
                                    folder cache, pool index, events)
```

The web console and the S3 listener are separate HTTP servers in one process. Buckets are created from the console (or with `CreateBucket` on the S3 endpoint), not by scanning Drive.

### Quick start

#### Docker Compose (recommended)

```bash
cp .env.example .env
# edit .env: set a strong S3DRIVE_UI_PASSWORD and your public URL
docker compose up -d --build
```

Open <http://localhost:8080>, sign in, and follow the in-app setup wizard.

#### Docker

```bash
docker build -t s3drive .
docker run -d --name s3drive \
  -p 9000:9000 -p 8080:8080 \
  -e S3DRIVE_PUBLIC_URL=http://localhost:8080 \
  -e S3DRIVE_UI_PASSWORD='change-me' \
  -v s3drive-data:/data \
  s3drive
```

#### Binary

Requires Go 1.27+.

```bash
make build
S3DRIVE_UI_PASSWORD='change-me' ./bin/s3drive
```

Data is stored in `./data` by default: `s3drive.db`, the generated `master.key`, and the upload spool directory.

### Google OAuth setup

s3drive uses **your own** Google OAuth client. The client secret is stored encrypted in SQLite (or can be supplied through environment variables).

1. Create a project at <https://console.cloud.google.com/> and enable **Google Drive API**.
2. Configure the **OAuth consent screen**. For personal/testing use, keep the app in *Testing* and add your Google address as a test user.
3. Add the scope `https://www.googleapis.com/auth/drive` (s3drive needs full Drive access to read and write file content).
4. Create credentials → **OAuth client ID** → application type **Web application**.
   - Desktop client IDs will **not** work.
5. Add the authorized redirect URI:
   - local: `http://localhost:8080/oauth/callback`
   - production: `https://your-host/oauth/callback`
   - It must exactly match `S3DRIVE_PUBLIC_URL + /oauth/callback`.
6. In s3drive open **Settings → Google OAuth client**, paste the client ID and secret, and save.
7. Open **Accounts → Connect Google account**, grant access, and repeat for every Drive you want to use.

The OAuth flow uses PKCE (S256), `access_type=offline`, and `prompt=consent`; only the refresh token is kept long-term. If Google does not return a refresh token, remove s3drive from your Google account permissions and connect again.

> Google classifies the Drive scope as restricted. Apps used by external users may need Google verification. Testing-mode apps are limited to the test users you add.

### First steps in the console

1. **Connect an account** (Accounts).
2. **Create a bucket** (Buckets) and choose the account that owns it. Buckets map to a Drive folder at the root of My Drive.
3. **Create an access key** (Access keys). The secret is shown once — copy it immediately.
4. Point any S3 client at `http://your-host:9000` with region `us-east-1` and the key pair.

Your browser may show the S3 endpoint as `localhost:9000`; set `S3DRIVE_PUBLIC_S3_URL` if clients reach it through a different hostname or TLS proxy.

### Using it from S3 clients

AWS CLI examples (path-style is required):

```bash
aws configure set region us-east-1
aws configure set aws_access_key_id YOUR_ACCESS_KEY
aws configure set aws_secret_access_key YOUR_SECRET_KEY

ENDPOINT=http://localhost:9000

aws --endpoint-url "$ENDPOINT" s3api list-buckets
aws --endpoint-url "$ENDPOINT" s3api create-bucket --bucket photos
aws --endpoint-url "$ENDPOINT" s3 cp ./photo.jpg s3://photos/2026/photo.jpg
aws --endpoint-url "$ENDPOINT" s3 ls s3://photos/2026/
aws --endpoint-url "$ENDPOINT" s3 cp s3://photos/2026/photo.jpg ./copy.jpg
aws --endpoint-url "$ENDPOINT" s3 presign s3://photos/2026/photo.jpg --expires-in 3600
```

Other clients: MinIO `mc` (`mc alias set s3drive http://localhost:9000 KEY SECRET`), rclone's S3 backend, Cyberduck, boto3, and the AWS SDKs all work with path-style addressing.

### Multi-account buckets and the pool

- **Pinned bucket** — every request for that bucket goes to the account chosen when the bucket was created. Fast and predictable.
- **Pool bucket** — a virtual bucket named by `pool_name` (default `pool`). It merges all connected accounts:
  - listing walks each account's pool folder, deduplicates by key, and applies the SQLite object index;
  - uploads go to the connected account with the most free space;
  - reads consult the object index first, then fall back to scanning accounts;
  - overwriting a pooled key removes the stale copy when it lived in another account.
- The pool appears automatically while it is enabled and at least one account is connected. It cannot be deleted or created manually.

Bucket names must be 3–63 characters, lowercase letters/numbers/dots/hyphens, and must not contain `..`, `.-`, or `-.` — the same DNS-compatible rules as S3. Avoid names that differ only by case.

### Configuration

| Variable                       | Default                     | Purpose                                           |
|--------------------------------|-----------------------------|---------------------------------------------------|
| `S3DRIVE_DATA_DIR`             | `./data`                    | SQLite DB, master key, spool                      |
| `S3DRIVE_S3_ADDR`              | `:9000`                     | S3 listener                                       |
| `S3DRIVE_UI_ADDR`              | `:8080`                     | Console listener                                  |
| `S3DRIVE_PUBLIC_URL`           | `http://localhost:8080`     | Public console URL, used in OAuth redirects       |
| `S3DRIVE_PUBLIC_S3_URL`        | empty                       | Public S3 URL shown in the console                |
| `S3DRIVE_MASTER_KEY`           | generated `data/master.key` | 32-byte base64/hex key for secret encryption      |
| `S3DRIVE_UI_PASSWORD`          | empty                       | Console password; if empty the console is open    |
| `S3DRIVE_SPOOL_DIR`            | `$DATA_DIR/tmp`             | Multipart/staging directory                       |
| `S3DRIVE_LOG_LEVEL`            | `info`                      | `debug`, `info`, `warn`, `error`                  |
| `S3DRIVE_TRUST_PROXY`          | `false`                     | Trust `X-Forwarded-Proto` for secure cookies/URLs |
| `S3DRIVE_GOOGLE_CLIENT_ID`     | empty                       | Optional OAuth client override (env wins)         |
| `S3DRIVE_GOOGLE_CLIENT_SECRET` | empty                       | Optional OAuth secret override                    |

Runtime settings that can be changed in the console: OAuth client, public URL, region label, pool name/enabled, CORS origins, site name.

**Back up `master.key` together with the database.** Losing it makes stored refresh tokens and S3 secrets unrecoverable. To supply your own key, generate one with `openssl rand -base64 32`. If you change `S3DRIVE_MASTER_KEY` later, existing secrets can no longer be decrypted.

### Reverse proxy and TLS

Run s3drive behind Caddy, nginx, or Traefik. Things to configure:

- Proxy both listeners, or only the console if S3 is private.
- Preserve `Host` and set `X-Forwarded-Proto: https`; set `S3DRIVE_TRUST_PROXY=true` so cookies are marked `Secure`.
- Set `S3DRIVE_PUBLIC_URL` to the external console URL — the OAuth redirect depends on it.
- Set `S3DRIVE_PUBLIC_S3_URL` to the external S3 URL if it differs.
- S3 request bodies can be large; raise proxy body limits and timeouts for uploads.

### Security notes

- Set `S3DRIVE_UI_PASSWORD` before exposing the console. Without it, anyone who can reach `:8080` has full access.
- Access-key secrets are shown once and stored encrypted; they are decrypted only to verify a request signature.
- Sessions are HMAC-signed, `HttpOnly`, `SameSite=Lax`, and invalidated on restart.
- State-changing console requests require a CSRF cookie/token pair; `POST /login` and `/lang` are covered too.
- Public bucket mode allows anonymous **GET/HEAD of objects** only. Bucket listings, writes, deletes, and bucket-level HEAD still require a signature.
- The console does not support multi-user roles: every signed-in browser has full control.
- Give s3drive its own Google OAuth client and treat the Drive accounts as the security boundary.

### S3 API support

Implemented:

- `ListBuckets`, `CreateBucket`, `HeadBucket`, `DeleteBucket` (bucket must be empty)
- `ListObjects`, `ListObjectsV2` (prefix, delimiter, max-keys, marker/continuation-token, start-after, encoding-type=url)
- `PutObject`, `GetObject`, `HeadObject`, `DeleteObject`, `DeleteObjects`, `CopyObject`
- `Range`, `If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since`
- Multipart: create, upload part, list parts, list uploads, complete, abort
- SigV4 authorization header and presigned query URLs
- `GetBucketLocation`, `GetBucketVersioning`, `GetBucketAcl`, `GetBucketCors`, `GetBucketTagging` and similar read-only stubs used by SDK probes
- Path-style `/{bucket}/{key}` addressing

Not implemented (returns an error or an empty stub): virtual-host-style buckets, bucket policies, ACL mutation, versioning, object lock, lifecycle, replication, website hosting, logging, notifications, server-side encryption controls, object tagging persistence, `GetObjectAttributes`, BitTorrent, POST object forms.

### Limitations

Drive is not S3. Expect these differences:

- **Upload quota**: Google limits uploads to roughly **750 GB per account per day**. The pool distributes writes but each account has its own limit.
- **Naming**: Drive searches names case-insensitively and allows duplicate names. Bucket code resolves by exact name and overwrites by name, but keys differing only by case can behave unpredictably. `/` and empty/`.`/`..` segments are rejected because they cannot map to Drive folders.
- **Listing order**: objects are ordered by Drive folder listing order (name), then merged. S3 promises byte-wise order; pagination still works, but the order may differ slightly with unusual characters.
- **No versions or undelete**: overwrites replace content; deletes are permanent (`files.delete`, not trash) to release quota.
- **Multipart staging**: parts are stored on local disk and concatenated into one temp file at completion, then uploaded. Completing a 100 GB multipart needs ~100 GB of free spool space.
- **ETags**: for reads, the Drive MD5 when available, otherwise the file ID. Multipart ETags use the standard `md5-of-part-md5s-N` format for the completed object, but Drive may report its own MD5 on later reads.
- **Metadata**: only content type is kept; S3 user metadata, storage classes, tags, and ACLs are not preserved.
- **Performance**: each object maps to a Drive API call. Listing is folder traversal, not a single indexed query. Latency is bounded by Drive, not by s3drive.
- **Quota accounting**: Drive counts trashed files and all files in the account, not just s3drive data.
- **Pool consistency**: the object index is best-effort. Files added to a pool folder outside s3drive are discovered by scanning; duplicate keys across accounts are deduplicated but not merged.
- **No HA**: SQLite and the spool directory are local. Run one instance per data directory.

### Development

```bash
make dev        # run with go run (data in ./data)
make build      # bin/s3drive
make test       # go test ./...
make vet        # go vet ./...
make fmt        # gofmt
make docker     # docker build -t s3drive .
```

Project layout:

```
cmd/s3drive/          entry point, listeners, graceful shutdown, maintenance
internal/config/      environment configuration and version
internal/secure/      AES-256-GCM secret box
internal/store/       SQLite schema and persistence
internal/google/      Drive REST + OAuth client
internal/drive/       S3 semantics on top of Drive (buckets, listing, pool)
internal/s3/          SigV4, S3 routing, XML, multipart
internal/webui/       htmx console, i18n, OAuth wizard
web/                  embedded templates and static assets
helper-projects/      reference implementations used during design
```

No test suite is included yet; `go vet ./...` and a manual smoke test against a real Drive account are the current checks. Contributions and bug reports are welcome.

---

## Türkçe

### Ne yapar?

- **S3 API** (`:9000`, path-style): bucket işlemleri, prefix/delimiter/sayfalama ile `ListObjectsV2`, Put/Get/Head/Delete/Copy, Range ve koşullu GET, multipart yükleme, presigned URL, `DeleteObjects`, SigV4 header ve query doğrulaması.
- **Web konsolu** (`:8080`): kontrol paneli ve kota, dosya tarayıcı/yükleme/indirme, bucket yönetimi, hesap bağlama, S3 erişim anahtarları, OAuth ayarları.
- **Google Drive arka ucu**: her bucket, My Drive kökü altında bir Drive klasörüdür. Nesne anahtarındaki `/` iç içe klasöre dönüşür.
- **Çoklu Google hesabı**: bir bucket'ı tek hesaba sabitleyin ve/veya tüm bağlı hesapları birleştiren sanal **pool** bucket'ını kullanın. Pool yüklemeleri en çok boş alanı olan hesaba gider; nesne→hesap eşlemesi SQLite'ta tutulur.
- **Güvenli varsayılanlar**: AES-256-GCM ile şifrelenmiş refresh token'lar, şifrelenmiş S3 anahtarları, isteğe bağlı konsol şifresi, CSRF koruması, imzalı oturum çerezleri, harici servis bağımlılığı yok.
- **Tek binary + Docker**: HTML/CSS/JS ve htmx `go:embed` ile gömülüdür. SQLite cgo gerektirmez (`modernc.org/sqlite`).

### Nasıl çalışır?

```
S3 istemcisi ──SigV4──▶ :9000 ──▶ drive servisi ──▶ Google Drive API
Tarayıcı     ──çerez──▶ :8080 ──▶ drive servisi ──▶ Google Drive API
                                  │
                                  └──▶ SQLite (hesaplar, bucket'lar,
                                       anahtarlar, klasör önbelleği,
                                       pool indeksi, olaylar)
```

Konsol ve S3 dinleyicisi aynı süreçte iki ayrı HTTP sunucusudur. Bucket'lar konsoldan (veya S3 üzerinden `CreateBucket` ile) oluşturulur; Drive taranarak otomatik bucket üretilmez.

### Hızlı başlangıç

#### Docker Compose (önerilen)

```bash
cp .env.example .env
# .env: güçlü bir S3DRIVE_UI_PASSWORD ve genel URL girin
docker compose up -d --build
```

<http://localhost:8080> adresini açın, giriş yapın ve kurulum sihirbazını izleyin.

#### Docker

```bash
docker build -t s3drive .
docker run -d --name s3drive \
  -p 9000:9000 -p 8080:8080 \
  -e S3DRIVE_PUBLIC_URL=http://localhost:8080 \
  -e S3DRIVE_UI_PASSWORD='degistir-beni' \
  -v s3drive-data:/data \
  s3drive
```

#### Binary

Go 1.27+ gerekir.

```bash
make build
S3DRIVE_UI_PASSWORD='degistir-beni' ./bin/s3drive
```

Veriler varsayılan olarak `./data` altındadır: `s3drive.db`, üretilen `master.key` ve yükleme geçici dizini.

### Google OAuth kurulumu

s3drive **kendi** Google OAuth istemcinizi kullanır. İstemci sırrı SQLite'ta şifreli tutulur (veya ortam değişkenleriyle verilebilir).

1. <https://console.cloud.google.com/> üzerinde proje oluşturun ve **Google Drive API**'yi etkinleştirin.
2. **OAuth consent screen** ayarlayın. Kişisel/test kullanımı için uygulamayı *Testing* modunda bırakıp Google adresinizi test kullanıcısı olarak ekleyin.
3. `https://www.googleapis.com/auth/drive` kapsamını ekleyin (s3drive dosya içeriğini okumak/yazmak için tam Drive erişimine ihtiyaç duyar).
4. Kimlik bilgileri → **OAuth client ID** → uygulama türü **Web application**.
   - Desktop türü **çalışmaz**.
5. Yetkili yönlendirme URI'sini ekleyin:
   - yerel: `http://localhost:8080/oauth/callback`
   - üretim: `https://alan-adiniz/oauth/callback`
   - Tam olarak `S3DRIVE_PUBLIC_URL + /oauth/callback` ile eşleşmelidir.
6. s3drive'da **Ayarlar → Google OAuth istemcisi** bölümüne client ID ve secret'ı girip kaydedin.
7. **Hesaplar → Google hesabı bağla** ile izin verin; kullanmak istediğiniz her Drive için tekrarlayın.

OAuth akışı PKCE (S256), `access_type=offline` ve `prompt=consent` kullanır; uzun vadede yalnızca refresh token saklanır. Google refresh token döndürmezse s3drive'ı Google hesabınızın izinlerinden kaldırıp yeniden bağlayın.

> Google, Drive kapsamını kısıtlı kapsam olarak sınıflandırır. Dış kullanıcılara açılan uygulamalar Google doğrulaması gerektirebilir. Testing modundaki uygulamalar yalnızca eklediğiniz test kullanıcılarıyla sınırlıdır.

### Konsolda ilk adımlar

1. **Hesap bağlayın** (Hesaplar).
2. **Bucket oluşturun** (Bucket'lar) ve sahibi olacak hesabı seçin. Bucket, My Drive kökünde bir Drive klasörüne karşılık gelir.
3. **Erişim anahtarı oluşturun** (Erişim anahtarları). Sır yalnızca bir kez gösterilir — hemen kopyalayın.
4. Herhangi bir S3 istemcisini `http://alan-adiniz:9000`, region `us-east-1` ve anahtar çiftiyle yapılandırın.

Tarayıcı S3 adresini `localhost:9000` olarak gösterebilir; istemciler farklı bir hostname veya TLS proxy üzerinden erişiyorsa `S3DRIVE_PUBLIC_S3_URL` ayarlayın.

### S3 istemcileriyle kullanım

AWS CLI örnekleri (path-style zorunludur):

```bash
aws configure set region us-east-1
aws configure set aws_access_key_id ERISIM_ANAHTARI
aws configure set aws_secret_access_key GIZLI_ANAHTAR

ENDPOINT=http://localhost:9000

aws --endpoint-url "$ENDPOINT" s3api list-buckets
aws --endpoint-url "$ENDPOINT" s3api create-bucket --bucket fotograflar
aws --endpoint-url "$ENDPOINT" s3 cp ./foto.jpg s3://fotograflar/2026/foto.jpg
aws --endpoint-url "$ENDPOINT" s3 ls s3://fotograflar/2026/
aws --endpoint-url "$ENDPOINT" s3 cp s3://fotograflar/2026/foto.jpg ./kopya.jpg
aws --endpoint-url "$ENDPOINT" s3 presign s3://fotograflar/2026/foto.jpg --expires-in 3600
```

Diğer istemciler: MinIO `mc` (`mc alias set s3drive http://localhost:9000 ANAHTAR SIR`), rclone S3 arka ucu, Cyberduck, boto3 ve AWS SDK'ları path-style adresleme ile çalışır.

### Çoklu hesap ve pool

- **Sabitlenmiş bucket** — o bucket'a giden tüm istekler, bucket oluşturulurken seçilen hesaba gider. Hızlı ve öngörülebilir.
- **Pool bucket** — `pool_name` (varsayılan `pool`) ile adlandırılan sanal bucket. Tüm bağlı hesapları birleştirir:
  - listeleme her hesabın pool klasörünü gezer, anahtara göre tekilleştirir ve SQLite nesne indeksini uygular;
  - yüklemeler en çok boş alanı olan hesaba gider;
  - okumalar önce nesne indeksine bakar, sonra hesapları tarar;
  - pool'daki bir anahtarın üzerine yazıldığında eski kopya başka hesaptaysa silinir.
- Pool, etkin olduğu ve en az bir hesap bağlı olduğu sürece otomatik görünür. Elle silinemez veya oluşturulamaz.

Bucket adları 3–63 karakter olmalı; küçük harf, rakam, nokta ve tire içermeli; `..`, `.-`, `-.` içermemelidir — S3'ün DNS uyumlu kuralları. Yalnızca büyük/küçük harfle ayrışan adlardan kaçının.

### Yapılandırma

| Değişken                       | Varsayılan                 | Amaç                                                  |
|--------------------------------|----------------------------|-------------------------------------------------------|
| `S3DRIVE_DATA_DIR`             | `./data`                   | SQLite DB, master key, geçici dosyalar                |
| `S3DRIVE_S3_ADDR`              | `:9000`                    | S3 dinleyicisi                                        |
| `S3DRIVE_UI_ADDR`              | `:8080`                    | Konsol dinleyicisi                                    |
| `S3DRIVE_PUBLIC_URL`           | `http://localhost:8080`    | Genel konsol URL'i, OAuth yönlendirmesinde kullanılır |
| `S3DRIVE_PUBLIC_S3_URL`        | boş                        | Konsolda gösterilen genel S3 URL'i                    |
| `S3DRIVE_MASTER_KEY`           | üretilen `data/master.key` | Sır şifreleme için 32 baytlık base64/hex anahtar      |
| `S3DRIVE_UI_PASSWORD`          | boş                        | Konsol şifresi; boşsa konsol açıktır                  |
| `S3DRIVE_SPOOL_DIR`            | `$DATA_DIR/tmp`            | Multipart/geçici dosya dizini                         |
| `S3DRIVE_LOG_LEVEL`            | `info`                     | `debug`, `info`, `warn`, `error`                      |
| `S3DRIVE_TRUST_PROXY`          | `false`                    | Güvenli çerez/URL için `X-Forwarded-Proto`'ya güven   |
| `S3DRIVE_GOOGLE_CLIENT_ID`     | boş                        | İsteğe bağlı OAuth client override (env önceliklidir) |
| `S3DRIVE_GOOGLE_CLIENT_SECRET` | boş                        | İsteğe bağlı OAuth secret override                    |

Konsoldan değiştirilebilen çalışma zamanı ayarları: OAuth istemcisi, genel URL, region etiketi, pool adı/etkinliği, CORS kaynakları, site adı.

**`master.key` dosyasını veritabanıyla birlikte yedekleyin.** Kaybedilirse saklanan refresh token'lar ve S3 sırları kurtarılamaz. Kendi anahtarınızı `openssl rand -base64 32` ile üretebilirsiniz. `S3DRIVE_MASTER_KEY` sonradan değiştirilirse mevcut sırlar çözülemez.

### Ters proxy ve TLS

s3drive'ı Caddy, nginx veya Traefik arkasında çalıştırın:

- İki dinleyiciyi de (veya S3 özel kalacaksa yalnızca konsolu) proxy'leyin.
- `Host` başlığını koruyun, `X-Forwarded-Proto: https` ekleyin ve çerezlerin `Secure` işaretlenmesi için `S3DRIVE_TRUST_PROXY=true` yapın.
- OAuth yönlendirmesi buna bağlı olduğundan `S3DRIVE_PUBLIC_URL`'i dış konsol URL'i yapın.
- Dış S3 adresi farklıysa `S3DRIVE_PUBLIC_S3_URL` ayarlayın.
- S3 istek gövdeleri büyük olabilir; proxy gövde limitlerini ve zaman aşımını yükseltin.

### Güvenlik notları

- Konsolu dışa açmadan önce `S3DRIVE_UI_PASSWORD` ayarlayın. Ayarlanmazsa `:8080`'e erişen herkes tam yetkiye sahiptir.
- Erişim anahtarı sırları bir kez gösterilir ve şifreli saklanır; yalnızca istek imzasını doğrulamak için çözülür.
- Oturumlar HMAC imzalıdır, `HttpOnly` ve `SameSite=Lax`'tır; süreç yeniden başlayınca geçersiz olur.
- Durum değiştiren konsol istekleri CSRF çerez/token çifti gerektirir; `POST /login` ve `/lang` de korunur.
- Genel bucket modu yalnızca nesnelere anonim **GET/HEAD** izni verir. Listeleme, yazma, silme ve bucket HEAD imza gerektirir.
- Konsolda çok kullanıcılı rol yoktur: giriş yapan her tarayıcı tam kontrole sahiptir.
- s3drive'a kendi Google OAuth istemcisini verin; güvenlik sınırı olarak Drive hesaplarını düşünün.

### S3 API desteği

Desteklenenler:

- `ListBuckets`, `CreateBucket`, `HeadBucket`, `DeleteBucket` (bucket boş olmalı)
- `ListObjects`, `ListObjectsV2` (prefix, delimiter, max-keys, marker/continuation-token, start-after, encoding-type=url)
- `PutObject`, `GetObject`, `HeadObject`, `DeleteObject`, `DeleteObjects`, `CopyObject`
- `Range`, `If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since`
- Multipart: create, upload part, list parts, list uploads, complete, abort
- SigV4 Authorization header ve presigned query URL'leri
- `GetBucketLocation`, `GetBucketVersioning`, `GetBucketAcl`, `GetBucketCors`, `GetBucketTagging` ve SDK denemelerinde kullanılan benzer salt-okunur stub'lar
- Path-style `/{bucket}/{key}` adresleme

Desteklenmeyenler (hata veya boş stub döner): virtual-host-style bucket, bucket policy, ACL değiştirme, versioning, object lock, lifecycle, replication, website hosting, logging, bildirimler, sunucu tarafı şifreleme kontrolleri, kalıcı object tagging, `GetObjectAttributes`, BitTorrent, POST object formları.

### Sınırlamalar

Drive bir S3 değildir. Bu farkları bekleyin:

- **Yükleme kotası**: Google, hesap başına günde yaklaşık **750 GB** yükleme sınırı koyar. Pool yazmaları dağıtır ama her hesabın kendi sınırı vardır.
- **Adlandırma**: Drive adları büyük/küçük harf duyarsız arar ve aynı ada izin verir. Kod tam adla çözer ve ada göre üzerine yazar; yalnızca büyük/küçük harfle ayrışan anahtarlar öngörülemez davranabilir. `/`, boş segment ve `.`/`..` segmentleri Drive klasörlerine eşlenemediği için reddedilir.
- **Listeleme sırası**: nesneler Drive klasör listeleme sırasına (ad) göre sıralanır ve birleştirilir. S3 bayt sırası garanti eder; sayfalama çalışır ama sıra olağan dışı karakterlerde biraz farklı olabilir.
- **Sürüm/geri alma yok**: üzerine yazma içeriği değiştirir; silmeler kalıcıdır (kota açılsın diye çöp kutusu değil `files.delete` kullanılır).
- **Multipart geçici alanı**: parçalar yerel diskte tutulur, tamamlamada tek geçici dosyada birleştirilir ve yüklenir. 100 GB'lık multipart tamamlama ~100 GB boş spool alanı ister.
- **ETag**: okumalarda Drive MD5'i varsa o, yoksa dosya kimliği. Multipart ETag tamamlanan nesne için standart `md5-of-part-md5s-N` biçimini kullanır; ancak Drive sonraki okumalarda kendi MD5'ini bildirebilir.
- **Meta veri**: yalnızca content type korunur; S3 kullanıcı meta verisi, storage class, tag ve ACL'ler saklanmaz.
- **Performans**: her nesne bir Drive API çağrısıdır. Listeleme tek indeksli sorgu değil, klasör gezintisidir. Gecikme s3drive'a değil Drive'a bağlıdır.
- **Kota muhasebesi**: Drive, yalnızca s3drive verisini değil hesaptaki tüm dosyaları ve çöptekileri sayar.
- **Pool tutarlılığı**: nesne indeksi en iyi çabadır. s3drive dışında pool klasörüne eklenen dosyalar tarama ile bulunur; hesaplar arası aynı anahtarlar tekilleştirilir ama birleştirilmez.
- **HA yok**: SQLite ve spool dizini yereldir. Veri dizini başına tek örnek çalıştırın.

### Geliştirme

```bash
make dev        # go run ile çalıştır (veriler ./data)
make build      # bin/s3drive
make test       # go test ./...
make vet        # go vet ./...
make fmt        # gofmt
make docker     # docker build -t s3drive .
```

Proje düzeni:

```
cmd/s3drive/          giriş noktası, dinleyiciler, kapanış, bakım
internal/config/      ortam yapılandırması ve sürüm
internal/secure/      AES-256-GCM sır kutusu
internal/store/       SQLite şeması ve kalıcılık
internal/google/      Drive REST + OAuth istemcisi
internal/drive/       Drive üzerinde S3 semantiği (bucket, listeleme, pool)
internal/s3/          SigV4, S3 yönlendirme, XML, multipart
internal/webui/       htmx konsolu, i18n, OAuth sihirbazı
web/                  gömülü şablonlar ve statik dosyalar
helper-projects/      tasarım sırasında kullanılan referans projeler
```

Henüz test paketi yok; mevcut kontroller `go vet ./...` ve gerçek bir Drive hesabına karşı elle duman testidir. Katkı ve hata bildirimleri memnuniyetle karşılanır.
