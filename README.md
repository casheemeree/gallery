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

## Interaction

- Drag in any direction to pan the canvas.
- A trackpad scrolls vertically and horizontally; `Shift + wheel` scrolls horizontally.
- Click an image to open the blurred preview.
- Use the centered plus button to upload JPEG, PNG, WebP, or GIF files up to 15 MB.
- Under 600 px the gallery uses 3 columns; at 600 px and above it uses 5.

## Authentication model

The browser requests a one-time nonce, derives a key from the 10-digit code with
PBKDF2, and sends an HMAC proof. The plain code is never included in the HTTP
request. Production stores only the derived `ACCESS_KEY` verifier in `.env`, not
the original code. Successful verification creates an HttpOnly, SameSite session
cookie and a separate CSRF token for uploads.

This protocol must still run over HTTPS: a ten-digit code has limited entropy,
and TLS protects the session and proof from network observers. Failed attempts
are rate-limited. For a larger public service, replace the shared code with user
accounts or a PAKE-based login.

## Configuration

Generate the production verifier and its matching random salt in a trusted
terminal; input is hidden:

```bash
python3 server.py generate-access-key
```

Copy `.env.example` to `/srv/capi-gallery/.env`, paste both printed values, set
permissions to `600`, and never add the file to Git. The standard-library server
reads environment variables directly, so either export them in your shell or let
the included systemd unit load the file.

Uploads are stored in `uploads/`; metadata is stored in `data/gallery.sqlite3`.
Both are intentionally excluded from Git and should be backed up separately.

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
