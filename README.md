# CAPI Gallery

A private, two-directional infinite image gallery with a checkerboard rhythm,
responsive 3/5-column layouts, encrypted challenge-response login, image upload,
and a glass-style interface.

## Run locally

The project has no third-party runtime dependencies.

```bash
ACCESS_CODE=1234567890 python3 server.py
```

Open <http://127.0.0.1:8080>. The default local code is `1234567890`.

## Interaction

- Drag in any direction to pan the canvas.
- A trackpad scrolls vertically and horizontally; `Shift + wheel` scrolls horizontally.
- Click an image to open the blurred preview.
- Use the centered plus button to upload JPEG, PNG, WebP, or GIF files up to 15 MB.
- Under 600 px the gallery uses 3 columns; at 600 px and above it uses 5.

## Authentication model

The 10-digit code lives only in the server environment. The browser requests a
one-time nonce, derives a key with PBKDF2, and sends an HMAC proof. The plain code
is never included in the HTTP request. Successful verification creates an
HttpOnly, SameSite session cookie and a separate CSRF token for uploads.

This protocol must still run over HTTPS: a ten-digit code has limited entropy,
and TLS protects the session and proof from network observers. Failed attempts
are rate-limited. For a larger public service, replace the shared code with user
accounts or a PAKE-based login.

## Configuration

Copy `.env.example` to the server's `/srv/capi-gallery/.env` and edit it. The
standard-library server reads environment variables directly, so either export
the file in your shell or let the included systemd unit load it.

Uploads are stored in `uploads/`; metadata is stored in `data/gallery.sqlite3`.
Both are intentionally excluded from Git and should be backed up separately.

## GitHub → server deployment

1. Create an empty GitHub repository and add it as `origin`.
2. Clone it on the server to `/srv/capi-gallery`.
3. Add the `.env`, install `deploy/capi-gallery.service`, and adapt the Nginx
   example to the real domain and TLS certificate.
4. Add GitHub repository secrets: `SERVER_HOST`, `SERVER_USER`, and `DEPLOY_KEY`.
5. A push to `main` runs tests and then calls `deploy/deploy.sh` over SSH.

The service user needs write access to `/srv/capi-gallery/data` and
`/srv/capi-gallery/uploads`. The deploy user needs narrowly scoped permission to
restart `capi-gallery` with `sudo`.
