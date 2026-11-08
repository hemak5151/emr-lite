# EMR Lite — dependency-free starter project

A small local prototype based on the supplied EMR project description. It prioritises a small installation footprint and demonstrates patient registration, role-based access, clinical record creation, versioned amendments, and audit events.

## Requirements
- Python 3.10 or newer
- No `pip install` commands and no external Python packages
- No Node.js, React, Docker, MongoDB, or separate database server

SQLite is included with Python. The database is created automatically at `data/emr.sqlite3` the first time the app starts.

## Run on Windows 10/11
1. Extract the ZIP file.
2. Open the extracted `emr_lite` folder.
3. In File Explorer, click the address bar, type `cmd`, and press Enter.
4. Run:
   ```bat
   py app.py
   ```
   If `py` is unavailable, try `python app.py`.
5. Open `http://127.0.0.1:8000` in your browser.
6. Stop the server with `Ctrl+C` in the command window.

## Demo accounts
All demo accounts use the initial password `ChangeMe123!`.

| Username | Role | Demonstration permissions |
|---|---|---|
| `doctor` | Doctor | View records, create clinical records, amend records with a reason |
| `nurse` | Nurse | View records and create nursing observations only |
| `admin` | Hospital administrator | Register patients and view the patient directory; no clinical-record access |
| `sysadmin` | System administrator | Patient directory and audit history; no automatic clinical-record access |

**Change demo passwords and remove demo accounts before any deployment.** This starter intentionally does not yet include a password-management screen.

## Included
- Local SQLite database with foreign-key enforcement and WAL mode
- PBKDF2-HMAC-SHA256 password hashing
- Random session tokens stored as hashes, HttpOnly/SameSite cookies, session expiry
- CSRF token checks for state-changing forms
- Backend role checks (not just hidden interface buttons)
- Patient global/local demo identifiers
- Clinical record metadata, version number, author and timestamps
- Amendment history with reason and optimistic version checking
- Audit events for login, patient viewing, record changes and denied access
- Login throttling (5 failed attempts per user/IP locks for 5 minutes), constant-time-ish unknown-user check
- Atomic version check on amendments; server-side date/sex validation
- Escaped user-supplied text and basic browser security headers
- Responsive HTML/CSS interface with no frontend framework

## Important scope and safety limitations
This is an **academic/local prototype**, not a production Electronic Medical Record system and not certified for clinical use. Use synthetic test data only. Do not enter real patient information, biometric data, passwords used elsewhere, or identifiable medical information.

The supplied project description includes major capabilities that need separate design and validation before implementation. This starter does **not** claim to implement:
- Real multi-hospital connectivity, federation, HL7 FHIR, ABDM/ABHA, DICOM, or hospital-system adapters
- Verified doctor registration with an authoritative professional registry
- Real patient identity proofing, biometric verification, duplicate resolution, or guardian workflows
- Consent lifecycle, emergency/break-glass access, or legal compliance
- Distributed synchronisation, hospital connectivity failure handling, or offline operation
- AI medical summarisation
- Production encryption/key management, hardened deployment, monitoring, backups, disaster recovery, or penetration-tested security
- A final clinical permission matrix or medical-record retention policy

The project description itself identifies central/federated/hybrid storage, exclusive-access meaning, patient login, retrieval scope, AI scope, network-failure behaviour and deployment target as open decisions. These must be agreed before expanding the prototype. A production system requires healthcare, security, privacy and legal review, threat modelling, comprehensive tests, secure hosting and operational controls.

## Data reset
Stop the app, then delete the `data` folder to remove the local demo database. It will be recreated with demo accounts on the next start.

## Project structure
```text
emr_lite/
  app.py
  README.md
  static/
    style.css
  data/                 # created automatically at runtime
```
