### Static Code Analyzer Application
---
What this scanner looks for:

Advanced OWASP Top 10 Rules: Add rules for all OWASP Top 10 categories (A01-A10) across all languages, including:

    A01: Broken Access Control: Detect insecure authorization patterns (e.g., missing role checks).
    A02: Cryptographic Failures: Flag weak algorithms (e.g., MD5, SHA-1) and insecure key storage.
    A03: Injection: Expand SQL, command, and code injection detection (e.g., string concatenation in queries).
    A04: Insecure Design: Identify insecure session management and logging of sensitive data.
    A05: Security Misconfiguration: Flag missing security headers and permissive CORS.
    A06: Vulnerable Components: Add SBOM scanning for package.json, pom.xml, etc., using CVE feeds.
    A07: Identification/Authentication Failures: Detect hardcoded credentials and weak session handling.
    A08: Software/Data Integrity Failures: Flag insecure deserialization and untrusted data parsing.
    A09: Security Logging Failures: Identify missing or excessive logging of sensitive data.
    A10: SSRF: Detect unvalidated URL fetches.


Common Attack Vectors: Include rules for additional attack vectors like CSRF, insecure file uploads, and path traversal.

Validation of Coding Techniques: Use OWASP Secure Coding Practices, SonarQube RSPEC rules, and Checkmarx SAST patterns to ensure rules align with best practices, reducing false positives and ensuring actionable findings.

SBOM Integration: Enhance dependency scanning for vulnerabilities in third-party libraries using CVE data (simulated via regex for known vulnerable versions).

Contextual Awareness: Add basic data flow analysis for injection and XSS by tracking variable assignments to sinks (e.g., eval(), innerHTML).

Performance and Scalability: Optimize regex patterns and database queries for 1.2M+ lines, using batch processing and indexing.

React App Enhancements: Add filters for OWASP categories and CVE matches, improve result visualization.
Docker and Ansible: Update to include CVE database initialization.

### Resources Used
---

OWASP Top 10: For comprehensive rule coverage.

OWASP Secure Coding Practices: For secure coding guidelines.

SonarQube RSPEC Rules: For precise vulnerability patterns (e.g., RSPEC-5144, RSPEC-5131).

Checkmarx SAST: For advanced rule inspiration (e.g., obfuscated code detection).

CVE Feeds: Simulated via regex for dependency vulnerabilities (e.g., lodash<4.17.21).

### QA Approach
---

Accuracy: Validate rules against OWASP/SonarQube/Checkmarx to ensure high true positives.

False Positives: Use contextual checks (e.g., variable tracking) to minimize noise.

Testing: Update tests to cover new rules, SBOM scanning, and DB performance.

Security: Ensure secure DB queries and JWT validation.

Scalability: Test with 1.2M-line codebase, expect ~5-15 minutes on 8-core CPU.

### Creator Notes
---

This is not meant to be a comprehensive SAST tool.  It's utilized for a quick basic security analyzer to ensure the low hanging fruit is taken cared of.  I advise you use Sonarqube, CodeQL, Snyk, or any other fully built out scanner when analyzing production ready code.