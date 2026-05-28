# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in TradeRunner, **please do NOT open a public GitHub issue**. Instead, email the maintainer directly so the issue can be patched before disclosure.

**Contact:** human.artem@icloud.com

Please include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- (Optional) Suggested fix

We aim to respond within 72 hours and ship a patch within 7 days for critical issues.

## What TradeRunner Protects

TradeRunner is a **personal crypto trading journal** that can be self-hosted or deployed as a multi-user SaaS. We protect:

- **User passwords**: hashed with Werkzeug PBKDF2-SHA256 (never stored in plaintext)
- **Exchange API keys**: encrypted at rest using **Fernet (AES-128-CBC + HMAC-SHA256)**. The encryption key is **derived from the user's password via Argon2id** and only exists in the active session — never persisted to disk.
- **Tenant isolation**: every database row has a `user_id` foreign key. All queries filter by the authenticated user. There is no cross-tenant SQL path in the codebase.
- **CSRF**: Origin/Referer check + session-bound CSRF token on all mutating endpoints.
- **Rate limiting**: `/api/sync` is limited to 1 call per 30 seconds per user to prevent abuse of exchange APIs.

## Zero-Knowledge Architecture

Even the server administrator **cannot decrypt** a user's API keys without their password. If a user forgets their password:
- Their trade history and goals remain accessible (not encrypted)
- Their exchange API keys are **unrecoverable** and must be re-entered

This is a deliberate trade-off to protect users from a malicious admin or a database breach.

## Recommended Production Hardening

When deploying TradeRunner:

1. **Use HTTPS only** (Railway/Render do this automatically)
2. **Use read-only API keys** on exchanges (TradeRunner never needs trade/withdraw permissions)
3. **Set a strong `FLASK_SECRET_KEY`** as an environment variable
4. **Enable PostgreSQL with backups** (Railway includes automated daily backups)
5. **Add Cloudflare** in front for DDoS protection and rate limiting
6. **Rotate keys quarterly** — TradeRunner shows a reminder after 90 days

## Out of Scope

These are **not** considered vulnerabilities:
- Information disclosure when running with `FLASK_DEBUG=1` (debug mode is for development only — never use in production)
- Self-XSS in user-supplied trade notes (notes are escaped on render)
- Brute-force on login (mitigated by Argon2id's intentionally slow KDF; consider adding fail2ban or Cloudflare Bot Management for further protection)
