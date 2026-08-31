# Dangerous Functions & Injection Vectors by Language

Read only the sections for languages actually present in the target. Each pattern
is a *candidate*, not a finding — every hit must survive Phase 3 verification
before it reaches the report.

## JavaScript / TypeScript
- **Dangerous**: `eval()`, `new Function()`, `setTimeout(string)`, `innerHTML`, `document.write`, `child_process.exec`, `execSync`, `dangerouslySetInnerHTML`.
- **SQLi**: `` sql.query(`SELECT * FROM users WHERE id = ${id}`) ``
- **Secrets**: hardcoded keys in frontend source (`const API_KEY = 'AIza...'`).
  - *Check before flagging*: publishable/anon keys (Stripe `pk_`, Supabase anon, Firebase web config) are **designed** to ship in client code. Flag only secret-side keys.
- **Fix**: parameterized queries, `textContent`, `DOMPurify`. Move secret-side keys server-side.

## Python
- **Dangerous**: `eval()`, `exec()`, `pickle.load()`, `os.system()`, `subprocess.*` with `shell=True`.
- **SQLi**: `cursor.execute("SELECT * FROM users WHERE id = " + user_id)`
  - *Check before flagging*: an f-string inside `text()` is only injectable if the interpolated value is **user-controlled**. Interpolating a hardcoded literal or an identifier read back from `information_schema` is safe — this is the single most common false positive in Python SAST.
- **Config**: `os.getenv("SECRET", "")` — an empty or placeholder fallback is insecure; raise instead.
- **Fix**: bound parameters (`:name` / `?`), `subprocess.run([...], shell=False)`, fail loudly on missing config.

## Java
- **Dangerous**: `Runtime.getRuntime().exec()`, `Statement.executeQuery()`.
- **XXE**: `DocumentBuilderFactory` / `SAXParserFactory` without `setFeature("...disallow-doctype-decl", true)`.
- **Deserialization**: `ObjectInputStream.readObject()` on untrusted bytes.
- **Fix**: `PreparedStatement`, disable external entities, avoid native Java deserialization.

## Go
- **Dangerous**: `os/exec.Command()` with unsanitized input; `template.HTML()` bypasses auto-escaping.
- **SQLi**: `db.Query("SELECT * FROM users WHERE id=" + id)`
- **Fix**: `db.Query("SELECT * FROM users WHERE id=$1", id)`, avoid `template.HTML()`.

## Rust
- **Dangerous**: `unsafe` blocks without justification, `std::process::Command` with user input.
- **Fix**: minimize `unsafe`, validate inputs before passing to system commands.

## C# / .NET
- **Dangerous**: `Process.Start()` with user input, `SqlCommand` without `SqlParameter`.
- **SQLi**: `new SqlCommand("SELECT * FROM Users WHERE Id=" + userId)`
- **Fix**: `SqlParameter`, avoid `Process.Start` with unsanitized input.

## PHP
- **Dangerous**: `eval()`, `system()`, `passthru()`, `mysql_query()` (removed in PHP 7).
- **SQLi**: `mysqli_query($conn, "SELECT * FROM users WHERE id=$id")`
- **Fix**: PDO prepared statements.

## Dependency scanning by ecosystem

Run what is **already installed**. Do not `pip install` or `npm install` a scanner
into the user's environment during a read-only audit.

| Ecosystem | Command |
| :--- | :--- |
| Node | `npm audit --audit-level=high` |
| Python | `pip-audit -r requirements.txt` (preferred), or `safety scan` |
| Java | `mvn dependency-check:check` |
| Go | `govulncheck ./...` |
| Rust | `cargo audit` |
| Any | `trivy fs .`, `osv-scanner -r .` |

**If no scanner is available**: say so explicitly in the report. You may list
pins that look outdated as *upgrade candidates requiring confirmation* — but
never state a CVE ID, a "fixed in" version, or an advisory as fact from memory.
Recalled vulnerability data is frequently wrong about which versions are
affected, and a fabricated CVE in a security report destroys trust in the
whole document.
