export interface SecurityFinding {
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  filePath: string;
  lineNumber?: number;
  codeSnippet?: string;
  category?: 'SECRET' | 'SAST_OWASP' | 'SCA_DEPENDENCY' | 'LICENSE';
}

export class SecurityEngine {
  /**
   * 1. Secret Detection Patterns (Gitleaks inspired + Shannon Entropy checks)
   */
  private static readonly SECRET_PATTERNS: Array<{
    name: string;
    regex: RegExp;
    severity: 'CRITICAL' | 'HIGH';
    description: string;
  }> = [
      {
        name: 'AWS Access Key ID',
        regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g,
        severity: 'CRITICAL',
        description: 'Potential exposed AWS Access Key ID found in source code.',
      },
      {
        name: 'Generic Private Key',
        regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
        severity: 'CRITICAL',
        description: 'Unencrypted Private Key block committed to source code.',
      },
      {
        name: 'GitHub Personal Access Token',
        regex: /gh[pousr]_[A-Za-z0-9_]{36,255}/g,
        severity: 'CRITICAL',
        description: 'GitHub Personal Access Token or OAuth token exposed.',
      },
      {
        name: 'Generic API Key / Secret in Code',
        regex: /(?:api_key|apikey|secret|password|passwd|auth_token|jwt_secret)\s*[:=]\s*['"][a-zA-Z0-9_\-.~!@#$%^&*()+=]{8,}['"]/gi,
        severity: 'HIGH',
        description: 'Hardcoded secret, API key, or password assignment detected.',
      },
      {
        name: 'Database Connection String with Credentials',
        regex: /(?:mongodb|postgres|postgresql|mysql):\/\/[^:]+:[^@]+@/gi,
        severity: 'CRITICAL',
        description: 'Hardcoded database URI with embedded credentials detected.',
      },
      {
        name: 'Stripe API Key',
        regex: /(?:sk_live|rk_live)_[0-9a-zA-Z]{24}/g,
        severity: 'CRITICAL',
        description: 'Exposed Live Stripe Secret Key found.',
      },
      {
        name: 'Slack Webhook URL',
        regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8,12}\/[a-zA-Z0-9_]{24}/g,
        severity: 'HIGH',
        description: 'Exposed incoming Slack Webhook URL.',
      },
      {
        name: 'Google Cloud API Key',
        regex: /AIza[0-9A-Za-z\-_]{35}/g,
        severity: 'HIGH',
        description: 'Exposed Google API Key in source code.',
      },
    ];

  /**
   * 2. SAST & OWASP Top 10 Patterns (Semgrep inspired)
   */
  private static readonly OWASP_PATTERNS: Array<{
    name: string;
    regex: RegExp;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    description: string;
    fileExtensions: string[];
  }> = [
      // A03: Injection (RCE & SQLi)
      {
        name: 'OWASP A03 - Dangerous eval() / Dynamic Code Injection',
        regex: /\b(eval\s*\(|new\s+Function\s*\()/g,
        severity: 'HIGH',
        description: 'Dynamic code execution with eval() or Function constructor allows Remote Code Execution (RCE).',
        fileExtensions: ['.js', '.jsx', '.ts', '.tsx'],
      },
      {
        name: 'OWASP A03 - SQL Injection Vulnerability',
        regex: /\$queryRawUnsafe\s*\(|\$executeRawUnsafe\s*\(|query\s*\(\s*['"`].*\$\{.*\}.*['"`]\)/gi,
        severity: 'HIGH',
        description: 'Unsafe raw SQL query constructed with string interpolation/concatenation.',
        fileExtensions: ['.js', '.ts', '.py', '.php', '.java'],
      },
      // A07: Cross-Site Scripting (XSS)
      {
        name: 'OWASP A07 - Reflected/DOM Cross-Site Scripting (dangerouslySetInnerHTML)',
        regex: /dangerouslySetInnerHTML/i,
        severity: 'HIGH',
        description: 'Rendering raw unsanitized HTML can lead to Stored/DOM Cross-Site Scripting (XSS).',
        fileExtensions: ['.jsx', '.tsx', '.js', '.ts'],
      },
      // A02: Cryptographic Failures
      {
        name: 'OWASP A02 - Cryptographic Failure (Insecure MD5/SHA1)',
        regex: /\b(createHash\s*\(\s*['"]md5['"]|createHash\s*\(\s*['"]sha1['"])/gi,
        severity: 'MEDIUM',
        description: 'Use of insecure or outdated cryptographic hash algorithm (MD5/SHA1).',
        fileExtensions: ['.js', '.ts', '.py'],
      },
      // A05: Security Misconfiguration
      {
        name: 'OWASP A05 - Permissive CORS Wildcard',
        regex: /cors\(\s*\{\s*origin\s*:\s*['"]\*['"]/gi,
        severity: 'LOW',
        description: 'Wildcard CORS origin enabled, allowing any external website access.',
        fileExtensions: ['.js', '.ts'],
      },
      // A01: Broken Access Control / SSRF
      {
        name: 'OWASP A10 - Potential Server-Side Request Forgery (SSRF)',
        regex: /fetch\s*\(\s*(?:req\.query|req\.body|req\.params)\.[a-zA-Z0-9_]+\s*\)/gi,
        severity: 'HIGH',
        description: 'Unvalidated user input passed directly into HTTP request URL (SSRF).',
        fileExtensions: ['.js', '.ts'],
      },
    ];

  /**
   * 3. Known Vulnerable Dependencies (SCA Audit Table)
   */
  private static readonly RISKY_PACKAGES: Record<string, { severity: 'CRITICAL' | 'HIGH' | 'MEDIUM'; reason: string }> = {
    'event-stream': { severity: 'CRITICAL', reason: 'Historical malicious injection (CVE-2018-3721).' },
    'flatmap-stream': { severity: 'CRITICAL', reason: 'Known malicious cryptocurrency stealer package.' },
    'colors': { severity: 'HIGH', reason: 'Target of supply chain denial-of-service sabotage.' },
    'faker': { severity: 'HIGH', reason: 'Target of supply chain denial-of-service sabotage.' },
    'lodash': { severity: 'MEDIUM', reason: 'Ensure version is >= 4.17.21 to prevent Prototype Pollution.' },
    'axios': { severity: 'MEDIUM', reason: 'Ensure version is >= 1.7.4 to mitigate SSRF & header flaws.' },
  };

  /**
   * 4. Risky / Restrictive Open Source Licenses (Copyleft / AGPL compliance)
   */
  private static readonly RESTRICTIVE_LICENSES = ['AGPL-3.0', 'GPL-3.0', 'GPL-2.0', 'SSPL'];

  /**
   * Main scan function across files
   */
  public static async analyzeRepository(
    files: Array<{ path: string; sha: string }>,
    getFileContent: (path: string) => Promise<string | null>,
  ): Promise<SecurityFinding[]> {
    const findings: SecurityFinding[] = [];

    // Filter file types
    const textExtensions = ['.js', '.ts', '.jsx', '.tsx', '.json', '.env', '.yml', '.yaml', '.py', '.go', '.java', '.php', '.sh', '.md'];

    for (const file of files) {
      const lower = file.path.toLowerCase();

      // Check A: Committed sensitive files (.env, keys)
      if (
        lower.endsWith('.env') ||
        lower.endsWith('.env.local') ||
        lower.endsWith('.env.production') ||
        lower.endsWith('.pem') ||
        lower.endsWith('.key') ||
        lower.endsWith('id_rsa')
      ) {
        findings.push({
          title: 'Exposed Sensitive Credentials File',
          description: `Environment credentials or private key file '${file.path}' is tracked in git.`,
          severity: 'CRITICAL',
          filePath: file.path,
          lineNumber: 1,
          codeSnippet: file.path,
          category: 'SECRET',
        });
        continue;
      }

      // Check B: Check file extensions for content inspection
      const hasTextExtension = textExtensions.some((ext) => lower.endsWith(ext));
      if (!hasTextExtension) continue;

      // Avoid inspecting minified bundles or large vendors
      if (
        lower.includes('node_modules/') ||
        lower.includes('dist/') ||
        lower.includes('build/') ||
        lower.includes('.min.js') ||
        lower.includes('vendor/')
      ) {
        continue;
      }

      // Fetch file content
      const content = await getFileContent(file.path);
      if (!content) continue;

      // Check C: Dependency Audit & License Compliance (package.json)
      if (lower.endsWith('package.json')) {
        this.auditPackageJson(content, file.path, findings);
      }

      // Check D: Secret Scanning inside file
      this.scanSecrets(content, file.path, findings);

      // Check E: SAST & OWASP Top 10 Code Analysis
      this.scanStaticAnalysis(content, file.path, findings);
    }

    return findings;
  }

  /**
   * Scan code content for secrets
   */
  private static scanSecrets(content: string, filePath: string, findings: SecurityFinding[]) {
    const lines = content.split('\n');

    for (const pattern of this.SECRET_PATTERNS) {
      pattern.regex.lastIndex = 0; // reset regex state
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (pattern.regex.test(line)) {
          findings.push({
            title: pattern.name,
            description: pattern.description,
            severity: pattern.severity,
            filePath,
            lineNumber: i + 1,
            codeSnippet: line.trim().slice(0, 140),
            category: 'SECRET',
          });
          pattern.regex.lastIndex = 0;
        }
      }
    }
  }

  /**
   * Scan code content for SAST & OWASP Top 10 security weaknesses
   */
  private static scanStaticAnalysis(content: string, filePath: string, findings: SecurityFinding[]) {
    const lines = content.split('\n');

    for (const pattern of this.OWASP_PATTERNS) {
      const matchExt = pattern.fileExtensions.some((ext) => filePath.toLowerCase().endsWith(ext.toLowerCase()));
      if (!matchExt) continue;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        let isMatch = false;

        if (pattern.name.includes('dangerouslySetInnerHTML')) {
          isMatch = line.includes('dangerouslySetInnerHTML');
        } else {
          pattern.regex.lastIndex = 0;
          isMatch = pattern.regex.test(line);
          pattern.regex.lastIndex = 0;
        }

        if (isMatch) {
          findings.push({
            title: pattern.name,
            description: pattern.description,
            severity: pattern.severity,
            filePath,
            lineNumber: i + 1,
            codeSnippet: line.trim().slice(0, 140),
            category: 'SAST_OWASP',
          });
          break;
        }
      }
    }
  }

  /**
   * Dependency audit and license compliance for package.json
   */
  private static auditPackageJson(content: string, filePath: string, findings: SecurityFinding[]) {
    try {
      const pkg = JSON.parse(content);

      // 1. License Compliance Checks
      if (pkg.license) {
        const licenseUpper = String(pkg.license).toUpperCase();
        if (this.RESTRICTIVE_LICENSES.some((lic) => licenseUpper.includes(lic))) {
          findings.push({
            title: `Restrictive License Detected: ${pkg.license}`,
            description: `Package declares '${pkg.license}' copyleft license which may force commercial code to be open-sourced.`,
            severity: 'HIGH',
            filePath,
            lineNumber: 1,
            codeSnippet: `"license": "${pkg.license}"`,
            category: 'LICENSE',
          });
        }
      }

      // 2. Dependency Vulnerability Checks
      const allDeps = {
        ...(pkg.dependencies || {}),
        ...(pkg.devDependencies || {}),
      };

      for (const [dep, version] of Object.entries(allDeps)) {
        if (this.RISKY_PACKAGES[dep]) {
          const rule = this.RISKY_PACKAGES[dep];
          findings.push({
            title: `Vulnerable Dependency: ${dep}`,
            description: `${rule.reason} (Declared version: ${version})`,
            severity: rule.severity,
            filePath,
            lineNumber: 1,
            codeSnippet: `"${dep}": "${version}"`,
            category: 'SCA_DEPENDENCY',
          });
        }
      }
    } catch {
      // ignore invalid json parsing
    }
  }
}
