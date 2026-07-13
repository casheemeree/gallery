# Private Gallery

A private, two-directional infinite image gallery with a checkerboard rhythm,
responsive 3/5-column layouts, encrypted challenge-response login, image upload,
and a glass-style interface.

## Run locally

The project has no third-party runtime dependencies.

```bash
ACCESS_CODE=1234567890 python3 server.py
```

Open <http://127.0.0.1:8080>. The default local code is `1234567890`.

The first production access code should be created with the access-code manager
described below; the local fallback is used only while the JSON file is absent.

## Interaction

- Drag in any direction to pan the canvas.
- A trackpad scrolls vertically and horizontally; `Shift + wheel` scrolls horizontally.
- Click an image to open the blurred preview.
- Hold `Delete` in the preview for two seconds to remove an image; releasing early resets the action.
- Use the centered plus button to upload JPEG, PNG, WebP, or GIF files up to 15 MB.
- Under 600 px the gallery uses 3 columns; at 600 px and above it uses 5.

Only images close to the viewport are requested. New uploads also receive a
browser-generated WebP thumbnail (up to 1024 px) for the gallery while preview
continues to use the original. Versioned image URLs are cached for one year.

## Authentication model

The browser requests a one-time nonce, derives a key from the 10-digit code with
PBKDF2, and sends an HMAC proof. The plain code is never included in the HTTP
request. Production stores only derived verifiers in `data/access-codes.json`,
never the original codes. Successful verification creates an HttpOnly,
SameSite=Strict session cookie and a separate CSRF token for uploads and deletion.

Sessions are stored in SQLite using a hash of the browser token, so restarting the
server does not sign visitors out. The cookie lasts up to 400 days and its expiry
is refreshed whenever the gallery is opened. Removing an access code also revokes
every session created with that code.

This protocol must still run over HTTPS: a ten-digit code has limited entropy,
and TLS protects the session and proof from network observers. Failed attempts
are rate-limited. For a larger public service, replace the shared code with user
accounts or a PAKE-based login.

## Access codes

The JSON file is stored at `data/access-codes.json` by default and is excluded
from Git. Manage it through the CLI so plain codes are never written to disk:

```bash
python3 server.py access-code add "Owner"
python3 server.py access-code add "Guest"
python3 server.py access-code list
python3 server.py access-code remove <id>
```

`add` asks for the 10-digit code twice using hidden input. The JSON contains a
shared random salt, PBKDF2 settings, labels, IDs and derived keys only. It is
written atomically with permissions `600`. Labels help identify a code; removal
uses the short ID printed by `list`.

Set `ACCESS_CODES_PATH` in `.env` if the file should live elsewhere. On the
server, run these commands as the service account so it retains ownership of the
file, for example `sudo -u www-data python3 server.py access-code list`.

## Configuration

Copy `.env.example` to `/srv/capi-gallery/.env`, set permissions to `600`, and
never add it to Git. The standard-library server reads environment variables
directly, so either export them in your shell or let the included systemd unit
load the file. Production must use HTTPS with `COOKIE_SECURE=1`.

Uploads and generated thumbnails are stored in `uploads/`; image metadata and
persistent sessions are stored in `data/gallery.sqlite3`. These files and the
access-code JSON are excluded from Git and should be backed up separately.
Deleting an upload removes its original and thumbnail. Repository-provided
images remain on disk but receive a persistent database tombstone, so Git stays
clean and the deleted image is no longer listed or served.

## GitHub → server deployment

1. Create an empty GitHub repository and add it as `origin`.
2. Clone it on the server to `/srv/capi-gallery`.
3. Add the `.env`, install `deploy/capi-gallery.service`, and adapt the Nginx
   example to the real domain and TLS certificate.
4. Add GitHub repository secrets: `SERVER_HOST`, `SERVER_USER`, and `DEPLOY_KEY`.
5. A push to `main` runs tests and then calls `deploy/deploy.sh` over SSH.

Until all three secrets are present, the workflow runs the tests and intentionally
skips deployment instead of failing while trying to configure SSH. A domain is not
needed for the SSH connection itself; it is needed later for the Nginx server name
and HTTPS certificate.

The service user needs write access to `/srv/capi-gallery/data` and
`/srv/capi-gallery/uploads`. The deploy user needs narrowly scoped permission to
restart `capi-gallery` with `sudo`.
