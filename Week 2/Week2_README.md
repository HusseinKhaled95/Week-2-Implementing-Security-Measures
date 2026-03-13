# 🔐 Cybersecurity Internship — Week 2: Security Implementation

**DevelopersHub Cybersecurity Internship Program**
**Week 2 — Implementing Security Measures**
**Application:** OWASP NodeGoat v1.3.0 (Secured)

---

## 📋 Summary

This document covers all security fixes implemented during Week 2. Every vulnerability identified in the Week 1 assessment has been addressed with production-grade code changes.

**Packages Installed:**
```bash
npm install validator bcrypt jsonwebtoken sanitize-html dotenv
```

---

## ✅ Fixes Applied

| ID | Vulnerability | Package Used | Status |
|----|--------------|--------------|--------|
| V-01 | Plaintext Password Storage | `bcrypt` | ✅ FIXED |
| V-02 | Server-Side Request Forgery | `validator` | ✅ FIXED |
| V-03 | Stored XSS via Memos | `sanitize-html` | ✅ FIXED |
| V-04 | Missing Security Headers | `helmet` | ✅ FIXED |
| V-05 | CSRF Protection Disabled | `csurf` | ✅ FIXED |
| V-06 | Session Fixation on Login | `express-session` | ✅ FIXED |
| V-08 | ReDoS Regex Backtracking | Manual fix | ✅ FIXED |
| V-09 | Log / CRLF Injection | Manual fix | ✅ FIXED |
| V-10 | Hardcoded Secrets | `dotenv` | ✅ FIXED |
| — | JWT Token Auth | `jsonwebtoken` | ✅ ADDED |

---

## 🔧 Fix 1 — Input Validation & Sanitization (validator)

**File:** `app/routes/session.js`

```javascript
const validator = require('validator');

// Validate email
if (email && !validator.isEmail(email)) {
    errors.emailError = 'Invalid email address.';
    return false;
}

// Escape and trim all user inputs
const safeUserName = validator.escape(validator.trim(userName));

// Strong password policy
if (!validator.isLength(password, { min: 8, max: 64 })) {
    errors.passwordError = 'Password must be 8–64 characters.';
}
if (!/(?=.*\d)(?=.*[a-z])(?=.*[A-Z])/.test(password)) {
    errors.passwordError = 'Needs uppercase, lowercase, and a digit.';
}
```

**File:** `app/routes/memos.js` — sanitize-html prevents stored XSS:

```javascript
const sanitizeHtml = require('sanitize-html');

const SANITIZE_OPTIONS = {
    allowedTags: ['b', 'i', 'em', 'strong', 'p', 'br'],
    allowedAttributes: {}
};

// BEFORE: memosDAO.insert(req.body.memo, callback);  ← raw HTML stored
// AFTER:
const cleanMemo = sanitizeHtml(rawMemo, SANITIZE_OPTIONS);
memosDAO.insert(cleanMemo, callback);
```

---

## 🔑 Fix 2 — Password Hashing (bcrypt)

**File:** `app/data/user-dao.js`

```javascript
const bcrypt = require('bcrypt');
const BCRYPT_SALT_ROUNDS = 12;

// BEFORE: password stored as plaintext ← CRITICAL vulnerability
// AFTER:
this.addUser = async (userName, firstName, lastName, password, email, callback) => {
    const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
    const user = {
        userName,
        password: hashedPassword  // ← bcrypt hash stored
    };
    // ...
};

// Login: constant-time comparison (prevents timing attacks)
const passwordMatch = await bcrypt.compare(password, user.password);
```

---

## 🎫 Fix 3 — Token-Based Authentication (jsonwebtoken)

**File:** `app/routes/session.js`

```javascript
const jwt = require('jsonwebtoken');

// Issue JWT on successful login
const token = jwt.sign(
    { id: user._id, userName: user.userName },
    jwtSecret,
    { expiresIn: '1h', algorithm: 'HS256' }
);
res.setHeader('X-Auth-Token', token);
```

**File:** `app/middleware/auth.js` — JWT verification middleware:

```javascript
const verifyJWT = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader?.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Missing Authorization header' });
    }
    const token = authHeader.split(' ')[1];
    try {
        req.user = jwt.verify(token, jwtSecret, { algorithms: ['HS256'] });
        next();
    } catch (err) {
        res.status(401).json({ error: err.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token' });
    }
};

// Usage: router.get('/api/secure', verifyJWT, handler);
```

---

## 🛡️ Fix 4 — Helmet.js Security Headers

**File:** `server.js`

```javascript
const helmet = require('helmet');

app.disable('x-powered-by');  // Remove Express fingerprint

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc:  ["'self'", "'unsafe-inline'"],
            objectSrc:  ["'none'"],
            frameSrc:   ["'none'"],
        }
    },
    frameguard:     { action: 'deny' },
    referrerPolicy: { policy: 'no-referrer' },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }
}));
```

Headers now added to every response:
- `Content-Security-Policy` — prevents XSS
- `X-Frame-Options: DENY` — prevents clickjacking
- `X-Content-Type-Options: nosniff` — prevents MIME sniffing
- `Strict-Transport-Security` — enforces HTTPS
- `Referrer-Policy: no-referrer` — prevents data leakage

---

## 🔒 Fix 5 — CSRF Protection

**File:** `server.js`

```javascript
const csrf = require('csurf');

// BEFORE: // const csrf = require('csurf');  ← commented out
// AFTER:
const csrfProtection = csrf({ cookie: false });
app.use(csrfProtection);
app.use((req, res, next) => {
    res.locals.csrftoken = req.csrfToken();
    next();
});
```

---

## 🔄 Fix 6 — Session Fixation Prevention

**File:** `app/routes/session.js`

```javascript
// BEFORE: req.session.userId = user._id;  ← old session ID kept
// AFTER:
req.session.regenerate((err) => {
    req.session.userId = user._id;  // stored in brand-new session ID
    return res.redirect('/dashboard');
});
```

---

## 🧪 Fix 7 — ReDoS Safe Regex

**File:** `app/routes/profile.js`

```javascript
// BEFORE: /([0-9]+)+\#/  ← catastrophic backtracking
// AFTER:
const bankRoutingRegex = /^[0-9]+#$/;  // anchored, linear O(n)
```

---

## 📝 Fix 8 — Log Injection Prevention

**File:** `app/routes/session.js`

```javascript
const sanitizeForLog = (input) =>
    typeof input === 'string'
        ? input.replace(/(\r\n|\r|\n)/g, '_').replace(/[^\x20-\x7E]/g, '?')
        : String(input);

// BEFORE: console.log('Invalid user: ', userName);  ← CRLF injection
// AFTER:
console.log('Invalid user:', sanitizeForLog(userName));
```

---

## 🔑 Fix 9 — Secrets Management (dotenv)

**File:** `config/env/all.js`

```javascript
require('dotenv').config();

module.exports = {
    // BEFORE: cookieSecret: 'session_cookie_secret_key_here',  ← hardcoded
    // AFTER:
    cookieSecret: process.env.COOKIE_SECRET,
    jwtSecret:    process.env.JWT_SECRET,
    cryptoKey:    process.env.CRYPTO_KEY,
};
```

**Setup:**
```bash
cp .env.example .env
# Edit .env and fill in strong random values
# Generate: node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

`.env` is in `.gitignore` — **never committed to version control.**

---

## ✅ Security Checklist

- [x] Validate all inputs with `validator`
- [x] Hash passwords with `bcrypt` (cost 12)
- [x] Use constant-time comparison for credentials
- [x] Enforce strong password policy (8+ chars, upper, lower, digit)
- [x] Sanitize all HTML input with `sanitize-html`
- [x] Issue JWT tokens on login
- [x] Verify JWT on protected routes
- [x] Enable Helmet.js security headers
- [x] Remove X-Powered-By header
- [x] Enable CSRF protection
- [x] Regenerate session ID on login
- [x] Harden session cookie (httpOnly, sameSite, maxAge)
- [x] Sanitize log inputs (CRLF prevention)
- [x] Fix ReDoS-vulnerable regex
- [x] Move secrets to environment variables
- [x] Block SSRF with URL allowlist + private IP filtering
- [ ] Enable HTTPS with TLS *(Week 3)*
- [ ] Encrypt PII fields with AES-256 *(Week 3)*
- [ ] Set up Winston logging *(Week 3)*

---

## 📁 Files Changed

| File | Change |
|------|--------|
| `app/data/user-dao.js` | bcrypt hashing + compare |
| `app/routes/session.js` | validator, JWT, session regenerate, sanitizeForLog |
| `app/routes/memos.js` | sanitize-html on all input |
| `app/routes/profile.js` | Safe regex, validator for profile fields |
| `app/routes/research.js` | SSRF allowlist + private IP blocker |
| `server.js` | Helmet, csurf, hardened session config |
| `config/env/all.js` | dotenv, process.env for all secrets |
| `app/middleware/auth.js` | *(new)* JWT middleware |
| `.env` | *(new)* Secret environment variables |
| `.gitignore` | Added .env |

---

*DevelopersHub Cybersecurity Internship — Deadline: March 23, 2026*
