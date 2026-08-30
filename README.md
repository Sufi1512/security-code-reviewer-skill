# 🛡️ Security Code Reviewer & Remediation Engine Skill (v3.1)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![AI Agent Compatibility](https://img.shields.io/badge/Agent_Support-Antigravity%20%7C%20Claude%20Code%20%7C%20Cursor%20%7C%20Windsurf-blue)](https://github.com/Sufi1512/security-code-reviewer-skill)

An enterprise-grade, production-ready **AI Agent Skill** for performing automated Static Application Security Testing (SAST), Threat Modeling, API Deep Scans, HIPAA Compliance audits, and prioritized remediation.

Designed for AI Coding Assistants (Google Antigravity, Claude Code, Cursor, Windsurf, Codex, etc.).

---

## 🌟 Key Features

* **🛡️ OWASP Top 10 & API Top 10 Coverage:** Automated detection of SQLi, XSS, CSRF, BOLA/IDOR, BFLA, SSRF, Mass Assignment, and JWT algorithm confusion.
* **🔑 Secret & `.env` Tracking Audits:** Detects hardcoded credentials, un-ignored `.env` files tracked in Git, and fallback development secrets.
* **🏥 HIPAA / Healthcare-Specific Audit:** Built-in verification for PHI access logging, audit trails, encryption at rest/transit, and LLM data handling policies.
* **🌐 Cross-Language Support:** Detection rules for JavaScript/TypeScript, Python, Java, Go, Rust, C#/.NET, and PHP.
* **🐳 IaC & Container Hardening:** Scans `Dockerfile` and `docker-compose.yml` for root users, exposed ports, and privileged execution.
* **🚫 False Positive Reduction:** Smart exclusion rules filtering test files, mocks, documentation, and error-handling strings.
* **📝 Artifact Report Generator:** Automatically outputs a structured `security_audit_report.md` with before/after remediation code and compliance mappings (GDPR, HIPAA, PCI-DSS).

---

## 💻 Installation

### 1. For Google Antigravity / AGY Agents
Copy the `.agents` folder to your project root or global config:
```bash
# In your project root:
mkdir -p .agents/skills/security-code-reviewer
# Copy SKILL.md into .agents/skills/security-code-reviewer/
```

### 2. For Claude Code
Copy `SKILL.md` to your `.claude` skills directory:
```bash
mkdir -p .claude/skills/security-code-reviewer
# Copy SKILL.md into .claude/skills/security-code-reviewer/
```

### 3. For Cursor
Create a rule in `.cursor/rules/security-code-reviewer.mdc` and paste the contents of `SKILL.md`.

---

## 🚀 How to Trigger the Skill

Once installed, your AI agent will automatically load this skill whenever you ask security-related questions:

```text
"Perform a full security review on this codebase."
"Check my backend API endpoints for OWASP Top 10 issues."
"Audit my Dockerfile and .env configuration for security risks."
"Verify HIPAA compliance and PHI access logging in my application."
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
