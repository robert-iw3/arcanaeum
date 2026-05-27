import re
from typing import Dict, List, Tuple

class LanguagePatterns:
    def __init__(self, config: dict):
        self.patterns = {
            'python': [
                (re.compile(r'\beval\s*\(', re.MULTILINE), 'eval()', 'Dynamic code execution, risks injection (OWASP A03:2021)'),
                (re.compile(r'\bos\.system\s*\(', re.MULTILINE), 'os.system()', 'System command execution, risks command injection (OWASP A03:2021)'),
                (re.compile(r'\bsubprocess\.run\s*\(', re.MULTILINE), 'subprocess.run()', 'Command injection if unsanitized (OWASP A03:2021)'),
                (re.compile(r'\bpickle\.loads\s*\(', re.MULTILINE), 'pickle.loads()', 'Insecure deserialization (OWASP A08:2021)'),
                (re.compile(r'\bunserialize\s*\(', re.MULTILINE), 'unserialize()', 'PHP deserialization, risks insecure deserialization (OWASP A08:2021)'),
                (re.compile(r'\bexecSQL\s*\(', re.MULTILINE), 'execSQL()', 'Potential SQL injection (OWASP A03:2021)'),
                (re.compile(r'\bpassword\s*=\s*[\'"].*?[\'"]', re.MULTILINE), 'password =', 'Hardcoded password detected (OWASP A07:2021, RSPEC-5144)'),
                (re.compile(r'\bhashlib\.(md5|sha1)\s*\(', re.MULTILINE), 'hashlib.md5/sha1()', 'Weak cryptography (OWASP A02:2021, RSPEC-5131)'),
                (re.compile(r'\bos\.path\.join\s*\(', re.MULTILINE), 'os.path.join()', 'Path traversal risk (OWASP A05:2021)'),
                (re.compile(r'\bdjango\.db\.raw\s*\(\s*[\'"][^\'"]+[\'"]\s*\)', re.MULTILINE), 'django.db.raw()', 'SQL injection risk (OWASP A03:2021)'),
                (re.compile(r'\bflask\.request\.args\.get\s*\(\s*[\'"][^\'"]+[\'"]\s*\)\s*\+\s*[\'"]', re.MULTILINE), 'flask.request.args.get()', 'XSS risk via concatenation (OWASP A07:2021)'),
                (re.compile(r'\bhttp\.get\s*\(\s*[\'"][^\'"]+[\'"]\s*\)', re.MULTILINE), 'http.get()', 'HTTP request, risks SSRF (OWASP A10:2021)'),
            ],
            'java': [
                (re.compile(r'\bRuntime\.getRuntime\s*\(\)\.exec\s*\(', re.MULTILINE), 'Runtime.getRuntime().exec()', 'System command execution, risks command injection (OWASP A03:2021)'),
                (re.compile(r'\bSystem\.getProperty\s*\(', re.MULTILINE), 'System.getProperty()', 'System property access, risks sensitive data exposure (OWASP A07:2021)'),
                (re.compile(r'\bXMLDecoder\s*\(', re.MULTILINE), 'XMLDecoder()', 'XML deserialization, risks insecure deserialization (OWASP A08:2021)'),
                (re.compile(r'\bHttpSession\.setAttribute\s*\(', re.MULTILINE), 'HttpSession.setAttribute()', 'Session attribute storage, risks exposure (OWASP A04:2021)'),
                (re.compile(r'\bObjectInputStream\.readObject\s*\(', re.MULTILINE), 'ObjectInputStream.readObject()', 'Java deserialization, risks insecure deserialization (OWASP A08:2021)'),
                (re.compile(r'\bSystem\.getenv\s*\(', re.MULTILINE), 'System.getenv()', 'Environment variable access, risks sensitive data exposure (OWASP A07:2021, RSPEC-5144)'),
                (re.compile(r'\bPreparedStatement\.setString\s*\(\s*[^,]+,\s*[^)]+\+\s*[^)]+\)', re.MULTILINE), 'PreparedStatement.setString()', 'SQL injection risk (OWASP A03:2021)'),
                (re.compile(r'\b(new\s+)?MessageDigest\.getInstance\s*\(\s*[\'"](MD5|SHA1)[\'"]\s*\)', re.MULTILINE), 'MessageDigest.getInstance(MD5/SHA1)', 'Weak cryptography (OWASP A02:2021, RSPEC-5131)'),
                (re.compile(r'\bSystem\.out\.println\s*\(.+password', re.MULTILINE), 'System.out.println(password)', 'Sensitive data logging (OWASP A09:2021)'),
                (re.compile(r'\bnew\s+File\s*\(\s*[^)]+\+\s*[^)]+\)', re.MULTILINE), 'new File()', 'Path traversal risk (OWASP A05:2021)'),
                (re.compile(r'\bhttp\.get\s*\(\s*[\'"][^\'"]+[\'"]\s*\)', re.MULTILINE), 'http.get()', 'HTTP request, risks SSRF (OWASP A10:2021)'),
            ],
            'javascript': [
                (re.compile(r'\beval\s*\(', re.MULTILINE), 'eval()', 'Dynamic code execution, risks injection (OWASP A03:2021)'),
                (re.compile(r'\bFunction\s*\(\s*[\'"][^\'"]+[\'"]\s*\)', re.MULTILINE), 'Function()', 'Code injection risk (OWASP A03:2021)'),
                (re.compile(r'\binnerHTML\s*=\s*[^;]+', re.MULTILINE), 'innerHTML=', 'XSS risk (OWASP A07:2021)'),
                (re.compile(r'\bdocument\.write\s*\(', re.MULTILINE), 'document.write()', 'Dynamic DOM manipulation, risks XSS (OWASP A07:2021)'),
                (re.compile(r'\bdocument\.execCommand\s*\(', re.MULTILINE), 'document.execCommand()', 'Dynamic DOM manipulation, risks XSS (OWASP A07:2021)'),
                (re.compile(r'\bcrypto\.createHash\s*\(\s*[\'"](md5|sha1)[\'"]\s*\)', re.MULTILINE), 'crypto.createHash("md5/sha1")', 'Weak cryptographic algorithm (OWASP A02:2021, RSPEC-5131)'),
                (re.compile(r'\beval\s*\(\s*atob\s*\(\s*[\'"].*?[\'"]\s*\)\s*\)', re.MULTILINE), 'eval(atob())', 'Obfuscated code execution (OWASP A08:2021, Checkmarx SAST)'),
                (re.compile(r'\beval\s*\(\s*decodeURIComponent\s*\(\s*[\'"].*?[\'"]\s*\)\s*\)', re.MULTILINE), 'eval(decodeURIComponent())', 'Obfuscated code execution (OWASP A08:2021, Checkmarx SAST)'),
                (re.compile(r'\bhttp\.get\s*\(\s*[\'"][^\'"]+[\'"]\s*\)', re.MULTILINE), 'http.get()', 'HTTP request, risks SSRF (OWASP A10:2021)'),
                (re.compile(r'\bapp\.use\s*\(\s*[\'"][^\'"]+[\'"]\s*\)', re.MULTILINE), 'app.use()', 'Middleware misconfiguration (OWASP A05:2021)'),
                (re.compile(r'\bJSON\.parse\s*\(', re.MULTILINE), 'JSON.parse()', 'JSON parsing, risks unvalidated input (OWASP A03:2021, RSPEC-5335)'),
                (re.compile(r'\bevalScript\s*\(', re.MULTILINE), 'evalScript()', 'Dynamic script execution (OWASP A03:2021, Checkmarx SAST)'),
                (re.compile(r'\bconsole\.log\s*\(.+password', re.MULTILINE), 'console.log(password)', 'Sensitive data logging (OWASP A09:2021)'),
            ],
            'go': [
                (re.compile(r'\bos\.Exec\s*\(', re.MULTILINE), 'os.Exec()', 'System command execution, risks command injection (OWASP A03:2021)'),
                (re.compile(r'\bhttp\.Get\s*\(', re.MULTILINE), 'http.Get()', 'HTTP request, risks SSRF (OWASP A10:2021)'),
                (re.compile(r'\bgob\.Decode\s*\(', re.MULTILINE), 'gob.Decode()', 'Insecure deserialization (OWASP A08:2021)'),
                (re.compile(r'\bsql\.Query\s*\(\s*[\'"][^\'"]+[\'"]\s*\)', re.MULTILINE), 'sql.Query()', 'SQL injection risk (OWASP A03:2021)'),
                (re.compile(r'\bfmt\.Println\s*\(.+password', re.MULTILINE), 'fmt.Println(password)', 'Sensitive data logging (OWASP A09:2021)'),
                (re.compile(r'\bcrypto/md5\b', re.MULTILINE), 'crypto/md5', 'Weak cryptography (OWASP A02:2021, RSPEC-5131)'),
            ],
            'ruby': [
                (re.compile(r'\beval\s*\(', re.MULTILINE), 'eval()', 'Dynamic code execution, risks injection (OWASP A03:2021)'),
                (re.compile(r'\b(system|exec)\s*\(', re.MULTILINE), 'system()/exec()', 'Command injection (OWASP A03:2021)'),
                (re.compile(r'\bOpenSSL\.Digest\.new\s*\(\s*[\'"](MD5|SHA1)[\'"]\s*\)', re.MULTILINE), 'OpenSSL::Digest.new("MD5/SHA1")', 'Weak cryptographic algorithm (OWASP A02:2021, RSPEC-5131)'),
                (re.compile(r'\bMarshal\.load\s*\(', re.MULTILINE), 'Marshal.load()', 'Insecure deserialization (OWASP A08:2021)'),
                (re.compile(r'\bActiveRecord::Base\.connection\.execute\s*\(\s*[\'"][^\'"]+[\'"]\s*\)', re.MULTILINE), 'ActiveRecord::Base.connection.execute()', 'SQL injection risk (OWASP A03:2021)'),
                (re.compile(r'\bputs\s*\(.+password', re.MULTILINE), 'puts(password)', 'Sensitive data logging (OWASP A09:2021)'),
                (re.compile(r'\bhttp\.get\s*\(\s*[\'"][^\'"]+[\'"]\s*\)', re.MULTILINE), 'http.get()', 'HTTP request, risks SSRF (OWASP A10:2021)'),
            ],
            'rust': [
                (re.compile(r'\bstd::process::Command::new\s*\(', re.MULTILINE), 'std::process::Command::new()', 'System command execution, risks command injection (OWASP A03:2021)'),
                (re.compile(r'\bserde_json::from_str\s*\(', re.MULTILINE), 'serde_json::from_str()', 'Insecure deserialization (OWASP A08:2021)'),
                (re.compile(r'\bprintln!\s*\(.+password', re.MULTILINE), 'println!(password)', 'Sensitive data logging (OWASP A09:2021)'),
                (re.compile(r'\bmd5::compute\b', re.MULTILINE), 'md5::compute', 'Weak cryptography (OWASP A02:2021, RSPEC-5131)'),
                (re.compile(r'\bhttp\.get\s*\(\s*[\'"][^\'"]+[\'"]\s*\)', re.MULTILINE), 'http.get()', 'HTTP request, risks SSRF (OWASP A10:2021)'),
            ],
            'php': [
                (re.compile(r'\bunserialize\s*\(', re.MULTILINE), 'unserialize()', 'PHP deserialization, risks insecure deserialization (OWASP A08:2021)'),
                (re.compile(r'\bsession_start\s*\(', re.MULTILINE), 'session_start()', 'Session management, verify secure configuration (OWASP A02:2021)'),
                (re.compile(r'\bhttp_response_code\s*\(', re.MULTILINE), 'http_response_code()', 'HTTP response, verify secure headers (OWASP A05:2021)'),
                (re.compile(r'\bcreate_function\s*\(', re.MULTILINE), 'create_function()', 'Dynamic function creation, risks injection (OWASP A03:2021)'),
                (re.compile(r'\bexec\s*\(', re.MULTILINE), 'exec()', 'Command injection (OWASP A03:2021)'),
                (re.compile(r'\bmysql_query\s*\(\s*[\'"][^\'"]+[\'"]\s*\)', re.MULTILINE), 'mysql_query()', 'SQL injection risk (OWASP A03:2021)'),
                (re.compile(r'\becho\s*\(.+password', re.MULTILINE), 'echo(password)', 'Sensitive data logging (OWASP A09:2021)'),
                (re.compile(r'\bmd5\s*\(', re.MULTILINE), 'md5()', 'Weak cryptography (OWASP A02:2021, RSPEC-5131)'),
                (re.compile(r'\bhttp\.get\s*\(\s*[\'"][^\'"]+[\'"]\s*\)', re.MULTILINE), 'http.get()', 'HTTP request, risks SSRF (OWASP A10:2021)'),
            ],
            'cpp': [
                (re.compile(r'\bstrcpy\s*\(', re.MULTILINE), 'strcpy()', 'Buffer overflow risk (OWASP A08:2021)'),
                (re.compile(r'\bstrcat\s*\(', re.MULTILINE), 'strcat()', 'Buffer overflow risk (OWASP A08:2021)'),
                (re.compile(r'\bsprintf\s*\(', re.MULTILINE), 'sprintf()', 'Format string vulnerabilities (OWASP A03:2021)'),
                (re.compile(r'\bstd::ifstream\s*\(', re.MULTILINE), 'std::ifstream()', 'Unauthorized file access risk (OWASP A01:2021)'),
                (re.compile(r'\bstd::ofstream\s*\(\s*[\'"][^\'"]+[\'"]\s*\)', re.MULTILINE), 'std::ofstream()', 'Insecure file upload risk (OWASP A03:2021)'),
                (re.compile(r'\bstd::cout\s*\(.+password', re.MULTILINE), 'std::cout(password)', 'Sensitive data logging (OWASP A09:2021)'),
                (re.compile(r'\bmd5\s*\(', re.MULTILINE), 'md5()', 'Weak cryptography (OWASP A02:2021, RSPEC-5131)'),
                (re.compile(r'\bhttp\.get\s*\(\s*[\'"][^\'"]+[\'"]\s*\)', re.MULTILINE), 'http.get()', 'HTTP request, risks SSRF (OWASP A10:2021)'),
            ],
            'c': [
                (re.compile(r'\bstrcpy\s*\(', re.MULTILINE), 'strcpy()', 'Buffer overflow risk (OWASP A08:2021)'),
                (re.compile(r'\bstrcat\s*\(', re.MULTILINE), 'strcat()', 'Buffer overflow risk (OWASP A08:2021)'),
                (re.compile(r'\bsprintf\s*\(', re.MULTILINE), 'sprintf()', 'Format string vulnerabilities (OWASP A03:2021)'),
                (re.compile(r'\bmd5\s*\(', re.MULTILINE), 'md5()', 'Weak cryptography (OWASP A02:2021, RSPEC-5131)'),
            ],
            'universal': [
                (re.compile(r'[\'"][0-9a-fA-F]{32}[\'"]', re.MULTILINE), 'Hardcoded secret', 'Hardcoded secret or API key detected (OWASP A07:2021, RSPEC-5144)'),
                (re.compile(r'\b[A-Za-z0-9+/]{20,}=*', re.MULTILINE), 'Base64-encoded secret', 'Potential base64-encoded secret (OWASP A07:2021, RSPEC-5144)'),
                (re.compile(r'\b[A-Za-z0-9+/]{40,}=*', re.MULTILINE), 'Base64-encoded API key', 'Potential base64-encoded API key (OWASP A07:2021, RSPEC-5144)'),
                (re.compile(r'\bgraphql\s*\(\s*[\'"]query\s*{.*mutation.*[\'"]\s*\)', re.MULTILINE), 'graphql(query/mutation)', 'GraphQL mutation injection risk (OWASP A03:2021)'),
                (re.compile(r'\bapi\.call\s*\(\s*[\'"][^\'"]+[\'"]\s*\)', re.MULTILINE), 'api.call()', 'API call, risks insecure API access (OWASP A04:2021)'),
                (re.compile(r'\blogger\.debug\s*\(', re.MULTILINE), 'logger.debug()', 'Debug logging, risks sensitive data exposure (OWASP A09:2021)'),
                (re.compile(r'\b(password|secret|apiKey)\s*=\s*[\'"][^\'"]+[\'"]', re.MULTILINE), 'Hardcoded credentials', 'Hardcoded credentials (OWASP A07:2021, RSPEC-5144)'),
                (re.compile(r'\bquery\s*{.*mutation', re.MULTILINE), 'graphql mutation', 'GraphQL mutation injection (OWASP A03:2021)'),
            ],
        }
        self.custom_functions = config.get('custom_functions', [])

    def get_patterns(self, language: str) -> List[Tuple[re.Pattern, str, str]]:
        patterns = self.patterns.get(language, []) + self.patterns.get('universal', [])
        for custom in self.custom_functions:
            try:
                pattern = re.compile(custom['function'], re.MULTILINE)
                patterns.append((pattern, custom['function'], custom['description']))
            except re.error:
                print(f"Invalid regex in custom_functions: {custom['function']}")
        return patterns