# Security Policy

## Supported Versions

The following versions of this project are currently being supported with security updates:

| Version | Supported          | Deprecated |
|---------|--------------------|------------|
| latest  | ✅ Yes             | ❌ No      |
| 1.x     | ❌ No              | ✅ Yes     |

Older versions are not maintained unless explicitly noted in the repository.

---

## Reporting a Vulnerability

If you discover a security vulnerability, please **do not open a public issue**. Instead, report it privately by emailing:

📧 **bepalo.dev@gmail.com**

Alternatively, you can use GitHub's private vulnerability reporting feature on the repository:

🔒 **[Submit a report](https://github.com/bepalo/jwt/security/advisories/new)**

We take all reports seriously and will respond as quickly as possible to confirm the issue and provide a resolution.

---

## Disclosure Policy

1. You report the vulnerability privately.
2. We acknowledge the report within **48 hours**.
3. We investigate and attempt to resolve the issue within **7–14 days**.
4. Once resolved, we may publish a security advisory and issue a patch release if needed.

---

## Recommendations for Users

- Always use the latest version of the library.
- Do not expose JWT secrets or keys in client-side code.
- Regularly audit your dependencies for vulnerabilities (`npm audit`, `deno audit`, etc.).

Thank you for helping make this project more secure!
