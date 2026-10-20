# Digital Legacy Manager

A secure system for organising, protecting and transferring digital assets to
authorised beneficiaries after death or incapacity.

**Live demo:** https://muku2006slm-creator.github.io/Digital-Legacy-Manager/

---

## What it does

The application implements the full custody-and-release lifecycle modelled in the
project's UML diagrams, across five roles:

| Role | Capabilities |
|---|---|
| **Asset Owner** | Register digital assets, protect them, create a digital will, assign beneficiaries, define transfer conditions |
| **Beneficiary** | Request access to an estate, track request progress, view and download released assets |
| **Verification Authority** | Verify or reject submitted death certificates |
| **Legal Executor** | Verify legal documents, approve or reject asset release, execute the release |
| **Administrator** | Manage accounts, suspend and restore users, inspect and export the audit log |

### Release workflow

A beneficiary never gains access directly. Every request passes through a
four-stage state machine, and assets stay in their protected form until the
final stage:

```
SUBMITTED ──► CERT_VERIFIED ──► EXECUTOR_APPROVED ──► RELEASED
    │               │
    └─ CERT_REJECTED└─ EXECUTOR_REJECTED
```

Approval by the Legal Executor is blocked unless a legal document reference is
supplied, and a beneficiary cannot raise a second request against an estate
while one is already open.

---

## Running it

No build step, no server, no dependencies.

```bash
git clone https://github.com/muku2006slm-creator/Digital-Legacy-Manager.git
cd Digital-Legacy-Manager
```

Then open `index.html` in any browser — or serve it locally:

```bash
python -m http.server 8000
# http://localhost:8000
```

## Demo accounts

All accounts use the password `demo1234`. On the sign-in screen you can click
any account to log straight in.

| Email | Role |
|---|---|
| `aarav@dlm.demo` | Asset Owner |
| `priya@dlm.demo` | Beneficiary |
| `rao@dlm.demo` | Verification Authority |
| `sharma@dlm.demo` | Legal Executor |
| `admin@dlm.demo` | Administrator |

### Suggested demo sequence

1. **Aarav** — add an asset, open the Digital Will tab, assign it to Priya
2. **Priya** — request access with certificate reference `DC/TN/2026/00417`
3. **Dr. Rao** — verify the certificate
4. **Adv. Sharma** — enter legal reference `PR/2026/118`, approve, then release
5. **Priya** — open *Released Assets*, view the now-readable contents, download one
6. **Admin** — open the *Audit Log* to show the complete trail

The Administrator's **Overview** tab has a *Reset to seed data* button that
restores the original state before a presentation.

---

## Technical notes

- Single self-contained `index.html` — HTML, CSS and vanilla JavaScript, no frameworks
- State persists in the browser's `localStorage`, so data survives a page reload
- Every significant action writes to an audit log, which can be exported as text
- Responsive down to 380px

### Scope and limitations

This is an academic demonstration of the workflow and domain model, not a
production security system. In particular:

- **Asset protection is simulated.** The "protected" state applies a reversible
  encoding purely so the locked and released states are visually distinguishable.
  It is not cryptography and provides no confidentiality.
- Accounts and data live only in the visitor's own browser. Nothing is
  transmitted or stored on a server, and each visitor sees their own copy.
- Authentication is illustrative; credentials are not hashed.

Do not enter real credentials or genuine personal documents.

---

## Project structure

```
Digital-Legacy-Manager/
├── index.html      # the complete application
├── README.md
└── src/, tests/    # FastAPI prototype from the earlier assignment
```
