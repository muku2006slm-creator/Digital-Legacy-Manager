# Digital Legacy Manager

A system for organising, encrypting and conditionally transferring digital
assets to authorised beneficiaries after death or incapacity.

This repository contains **two things**:

| | What it is | How to run it |
|---|---|---|
| **Full application** | Node.js backend with SQLite, real authentication and AES-256-GCM encryption | `node server.js` → http://localhost:3000 |
| **Browser preview** | A single static page for viewing the interface without installing anything | [Open the live preview](https://muku2006slm-creator.github.io/Digital-Legacy-Manager/) |

The browser preview exists so the interface can be viewed instantly from any
device. It runs entirely in the visitor's browser, stores data only in that
browser, and **simulates** asset protection rather than encrypting anything.
It is a shop window, not the product.

**The full application is the real system.** Everything below describes it.

---

## Running the full application

Requires Node.js 18 or newer ([nodejs.org](https://nodejs.org)). There are no
dependencies to install — the server uses only the Node standard library.

```bash
git clone https://github.com/muku2006slm-creator/Digital-Legacy-Manager.git
cd Digital-Legacy-Manager
node server.js
```

Then open **http://localhost:3000**.

On Windows you can instead double-click **`start.bat`**, which starts the
server and opens the browser for you. Press `Ctrl+C` in the terminal to stop.

---

## Demo accounts

All accounts use the password `demo1234`. The sign-in screen lists them —
click any one to sign in.

| Email | Role |
|---|---|
| `aarav@dlm.demo` | Asset Owner |
| `priya@dlm.demo` | Beneficiary |
| `rao@dlm.demo` | Verification Authority |
| `sharma@dlm.demo` | Legal Executor |
| `admin@dlm.demo` | Administrator |

### Walkthrough

1. **Aarav (owner)** — add an asset, click *Decrypt & view*, then assign it to
   Priya under *Digital Will*
2. **Priya (beneficiary)** — request access with certificate `DC/TN/2026/00417`
3. **Dr. Rao (verifier)** — verify the certificate
4. **Adv. Sharma (executor)** — try *Approve release* with an empty legal
   reference to see the server reject it, then enter `PR/2026/118` and approve
   and release
5. **Priya** — open *Released Assets*, decrypt, download
6. **Admin** — inspect the *Audit Log*

The Administrator's Overview tab has a **Reset to seed data** button.

---

## Architecture

```
Browser (public/index.html)
    │  fetch() over HTTP, session cookie
    ▼
Node.js HTTP server (server.js)
    │  authentication · role checks · AES-256-GCM
    ▼
SQLite database (data/dlm.db)
```

The browser holds no business rules. Every authorisation decision is made on
the server, so a restriction cannot be bypassed by editing the page.

### Security implementation

| Concern | Implementation |
|---|---|
| Password storage | `scrypt` with a per-user 16-byte random salt, compared in constant time |
| Sessions | HMAC-SHA256 signed tokens in `HttpOnly`, `SameSite=Strict` cookies, 8-hour expiry |
| Asset encryption | AES-256-GCM with a per-asset random IV; the authentication tag is verified on read |
| Key separation | Each owner's key is derived from the master key via HKDF, so one owner's key cannot decrypt another's assets |
| Authorisation | Enforced per route on the server; a beneficiary receives plaintext only once the release workflow has completed |
| Audit | Every significant action is recorded server-side, including denied access attempts |
| Path traversal | Static paths are resolved and confirmed to stay within `public/` |

Asset contents are never written to the database in readable form:

```bash
# The seed data contains this recovery code, but the database does not.
grep -c "4821-9930-1174" data/dlm.db      # → 0
grep -c "Primary Email Account" data/dlm.db  # → matches
```

Names and descriptions are stored in the clear so they remain searchable;
contents are ciphertext.

### Verifying that authorisation is server-side

A beneficiary who bypasses the interface entirely and calls the API directly is
still refused, and the attempt is logged. With a freshly reset database:

```bash
# Sign in as the beneficiary, then request an asset that has not been released
curl -s -c c.txt -X POST http://localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"priya@dlm.demo","password":"demo1234"}'

curl -s -b c.txt http://localhost:3000/api/assets/a1/content
# → {"error":"You are not authorised to read this asset. ..."}
```

The administrator's audit log then shows an `ACCESS_DENIED` entry.

### Release state machine

```
SUBMITTED ──► CERT_VERIFIED ──► EXECUTOR_APPROVED ──► RELEASED
    │               │
    └─CERT_REJECTED └─EXECUTOR_REJECTED
```

Transitions are validated on the server: the executor cannot approve a request
whose certificate has not been verified, approval requires a legal document
reference, and release requires prior approval.

---

## API

| Method | Endpoint | Role | Purpose |
|---|---|---|---|
| POST | `/api/auth/login` | — | Sign in, set session cookie |
| POST | `/api/auth/logout` | any | Clear session |
| GET | `/api/me` | — | Current user and storage backend |
| GET | `/api/assets` | any | List assets (metadata only) |
| POST | `/api/assets` | owner | Create and encrypt an asset |
| DELETE | `/api/assets/:id` | owner | Delete an asset |
| GET | `/api/assets/:id/content` | gated | Decrypt — owner, or beneficiary post-release |
| GET/POST/PATCH | `/api/will` | owner | Read, create, update the digital will |
| POST | `/api/will/allocate` | owner | Assign an asset to a beneficiary |
| GET | `/api/requests` | any | List requests visible to the caller |
| POST | `/api/requests` | beneficiary | Raise an access request |
| POST | `/api/requests/:id/verify` | verifier | Verify or reject a certificate |
| POST | `/api/requests/:id/approve` | executor | Approve or reject release |
| POST | `/api/requests/:id/release` | executor | Execute the release |
| GET | `/api/released` | beneficiary | Estates released to the caller |
| GET | `/api/notifications` | any | Caller's notifications |
| GET/POST | `/api/users` | admin | List or create accounts |
| PATCH | `/api/users/:id` | admin | Suspend or restore an account |
| GET | `/api/audit` | admin | Audit log |
| GET | `/api/stats` | admin | System statistics |
| POST | `/api/admin/reset` | admin | Restore seed data |

---

## Repository layout

```
Digital-Legacy-Manager/
├── server.js           # backend: HTTP server, auth, crypto, database
├── public/
│   └── index.html      # frontend for the full application
├── index.html          # standalone browser preview (GitHub Pages)
├── start.bat           # Windows launcher
├── package.json
└── data/               # created on first run; not in version control
```

The server uses the built-in `node:sqlite` module when available (Node 22.5+)
and falls back to a JSON file on older versions. `data/` holds the database and
the generated session and encryption keys, and is excluded from version
control, so a fresh clone creates a new database with the seed accounts.

---

## Scope

This is an academic project. The cryptography, authentication and authorisation
in the full application are genuinely implemented rather than simulated, but
several things a production system would require are out of scope: TLS, rate
limiting and account lockout, key management in a hardware module or secrets
service, password reset, multi-factor authentication, and a real identity check
on submitted death certificates.

Do not enter real credentials or genuine personal documents.
