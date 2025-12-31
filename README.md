# 🔴 Vulnerable Node.js Application (Testing Only)

> ⚠️ **WARNING**: This folder contains intentionally vulnerable code for testing Semgrep detection.
> **DO NOT deploy to production or use in any real application!**

## Purpose

This folder is designed to test AppSec Sentinel's ability to:
1. Detect SAST vulnerabilities in JavaScript/Node.js via Semgrep
2. Detect SCA vulnerabilities via npm dependency scanning
3. Triage findings and generate fixes

## Files

| File | Vulnerabilities |
|------|-----------------|
| `app.js` | SQL Injection, Command Injection, XSS, Path Traversal, Prototype Pollution, eval(), SSRF, Open Redirect, ReDoS |
| `auth.js` | JWT Issues, Weak Crypto, Insecure Random, Timing Attacks, eval(), Dynamic require(), Hardcoded Secrets |
| `database.js` | SQL/NoSQL Injection, File System Issues, Command Injection, Prototype Pollution, SSRF, Deserialization |
| `package.json` | 50+ packages with known CVEs (lodash, express, axios, jsonwebtoken, etc.) |

## Vulnerability Summary

### SAST Vulnerabilities (Code Issues)

| Category | Count | Files |
|----------|-------|-------|
| SQL Injection | 8+ | app.js, database.js |
| NoSQL Injection | 4+ | app.js, database.js |
| Command Injection | 5+ | app.js, database.js |
| XSS | 3+ | app.js |
| Path Traversal | 4+ | app.js, database.js |
| Prototype Pollution | 4+ | app.js, database.js |
| eval() / new Function() | 5+ | app.js, auth.js |
| Hardcoded Secrets | 10+ | all files |
| Weak Crypto | 4+ | app.js, auth.js |
| Insecure Random | 4+ | app.js, auth.js |
| SSRF | 3+ | app.js, database.js |
| ReDoS | 4+ | app.js, auth.js |
| JWT Vulnerabilities | 3+ | auth.js |
| Insecure SSL/TLS | 2+ | auth.js |

### SCA Vulnerabilities (Dependency Issues)

| Severity | Example Packages |
|----------|------------------|
| **Critical** | lodash@4.17.11 (Prototype Pollution), node-serialize@0.0.4 (RCE) |
| **High** | express@4.16.0, axios@0.18.0, jsonwebtoken@8.3.0, js-yaml@3.12.0 |
| **Medium** | handlebars@4.0.0, ejs@2.5.6, marked@0.3.6, tar@4.4.0 |
| **Low** | minimist@1.2.0, moment@2.19.0, helmet@3.12.0 |

### Notable CVEs in Dependencies

| Package | CVE | Severity | Description |
|---------|-----|----------|-------------|
| lodash@4.17.11 | CVE-2019-10744 | Critical | Prototype Pollution |
| node-serialize@0.0.4 | CVE-2017-5941 | Critical | Remote Code Execution |
| express@4.16.0 | CVE-2019-5413 | High | Open Redirect |
| axios@0.18.0 | CVE-2019-10742 | High | SSRF |
| js-yaml@3.12.0 | CVE-2019-7164 | High | Code Execution |
| jsonwebtoken@8.3.0 | CVE-2022-23529 | High | Algorithm Confusion |
| handlebars@4.0.0 | CVE-2019-19919 | Critical | Prototype Pollution |
| tar@4.4.0 | CVE-2018-20834 | High | Arbitrary File Overwrite |

## Testing Commands

```bash
# Scan with Semgrep locally
semgrep --config auto vulnerable_node_app/

# Scan for JavaScript-specific rules
semgrep --config p/javascript vulnerable_node_app/
semgrep --config p/nodejs vulnerable_node_app/
semgrep --config p/express vulnerable_node_app/
semgrep --config p/jwt vulnerable_node_app/

# Security-focused scan
semgrep --config p/security-audit vulnerable_node_app/

# Test via AppSec Sentinel
# In the ADK Web UI, try:
# "Get all JavaScript findings from vulnerable_node_app"
# "Triage the critical SCA findings and create PRs"
```

## Expected Semgrep Rules to Trigger

### SAST Rules
- `javascript.lang.security.audit.sqli.*`
- `javascript.lang.security.audit.command-injection.*`
- `javascript.express.security.audit.xss.*`
- `javascript.lang.security.detect-eval.*`
- `javascript.lang.security.detect-non-literal-require.*`
- `javascript.lang.security.audit.prototype-pollution.*`
- `javascript.express.security.audit.express-open-redirect.*`
- `javascript.lang.security.audit.path-traversal.*`
- `javascript.lang.security.audit.crypto-*`
- `javascript.lang.security.audit.insecure-random.*`
- `javascript.jwt.security.*`
- `javascript.lang.security.audit.regex-dos.*`
- `generic.secrets.security.*`

### SCA Rules
- `supply-chain` rules for vulnerable npm packages
- Dependency scanning for known CVEs

