# Compliance-Specific Checks

Read this file **only** when the user has named a regime, or when the codebase
plainly handles regulated data (patient records, cardholder data, EU personal data).

Do not attach compliance citations to findings by reflex. A citation on a finding
in an unregulated system is noise, and a wrong article number is worse than none.
Cite an article only when you can name the specific control the finding violates.

---

## HIPAA / Healthcare (PHI)

### Access Controls — §164.312(a)
- [ ] **Unique user identification**: every user has a unique ID; no shared accounts.
- [ ] **Emergency access**: a documented break-glass procedure exists.
- [ ] **Automatic logoff**: sessions expire after inactivity (15 minutes is the common bar for PHI access).
- [ ] **Encryption**: PHI encrypted at rest (AES-256) and in transit (TLS 1.2+).

### Audit Controls — §164.312(b)
- [ ] **PHI access logging**: every read/write/update/delete logged with who, what, when, where.
- [ ] **Log integrity**: audit logs append-only, stored separately from application data.
- [ ] **Retention**: 6 years minimum.
- [ ] **Anomaly detection**: alerts on bulk downloads and off-hours access.

### Integrity — §164.312(c)
- [ ] **Checksums/signatures**: PHI alteration in transit is detectable.
- [ ] **Input validation**: PHI validated and sanitized before storage.

### Transmission Security — §164.312(e)
- [ ] **No plaintext PHI in transit**.
- [ ] **Minimum necessary**: PHI responses carry only the fields the client needs.
- [ ] **No PHI in URLs**: query parameters are logged by servers, proxies, and browser history.
- [ ] **No PHI in logs**: no names, IDs, diagnoses, or medical data in application or error logs.

### Business Associate Agreements
- [ ] **Third parties**: every cloud service, API, and LLM provider that may touch PHI is covered by a BAA.
- [ ] **LLM data handling**: the provider does not retain or train on submitted data. Check the actual plan terms — the default consumer tier and the enterprise tier usually differ, and the code cannot tell you which one the API key belongs to. Flag this as a question for the user, not as a finding.

---

## PCI-DSS (cardholder data)

- [ ] **Req 3**: PAN never stored unless required; when stored, rendered unreadable (truncation, tokenization, or strong crypto). Never store CVV/CVC after authorization.
- [ ] **Req 4**: strong cryptography on transmission across open networks.
- [ ] **Req 6.5**: the injection, auth, and access-control classes covered by the main checklist.
- [ ] **Req 8**: unique IDs, MFA for all non-console administrative access.
- [ ] **Req 10**: audit trails linking access to individual users.
- [ ] **No PAN in logs, URLs, or error messages.**

---

## GDPR (EU personal data)

- [ ] **Art. 32** — security of processing: encryption at rest and in transit, tested regularly.
- [ ] **Art. 17** — erasure: a real deletion path exists, including backups and derived stores (search indexes, caches, embeddings, model context).
- [ ] **Art. 25** — data minimisation by default: endpoints return only necessary fields.
- [ ] **Art. 33** — breach notification within 72 hours: logging is sufficient to detect and scope a breach.
- [ ] **Art. 30** — records of processing: third-party processors documented.
- [ ] **Transfers**: personal data leaving the EEA has a lawful transfer mechanism. LLM and embedding providers count.

---

## SOC 2

Less a code checklist than an evidence one. From the codebase you can support:

- [ ] **Change management**: reviewed and traceable changes (branch protection, PR review).
- [ ] **Logical access**: RBAC enforced in code, access revocation actually effective (see the JWT revocation note in `api-security.md` — a process-local blacklist is not revocation).
- [ ] **Monitoring**: security-relevant events logged and alertable.
- [ ] **Vulnerability management**: automated dependency scanning in CI with a defined remediation window.
