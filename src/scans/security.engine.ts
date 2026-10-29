export interface SecurityFinding {
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  filePath: string;
  lineNumber?: number;
  codeSnippet?: string;
}

export class SecurityEngine {
  /**
   * 1. Secret Detection Patterns (Regex based with line number extraction)
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
  ];

  /**
   * 2. Static Code Analysis (SAST) Patterns
   */
  private static readonly SAST_PATTERNS: Array<{
    name: string;
    regex: RegExp;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    description: string;
    fileExtensions: string[];
  }> = [
    {
      name: 'Dangerous eval() / Function constructor',
      regex: /\b(eval\s*\(|new\s+Function\s*\()/g,
      severity: 'HIGH',
      description: 'Use of eval() or dynamic Function execution allows Code Injection (RCE).',
      fileExtensions: ['.js', '.jsx', '.ts', '.tsx'],
    },
    {
      name: 'SQL Injection Vulnerability (String Concatenation)',
      regex: /\$queryRawUnsafe\s*\(|\$executeRawUnsafe\s*\(|query\s*\(\s*['"`].*\$\{.*\}.*['"`]\)/gi,
      severity: 'HIGH',
      description: 'Unsafe raw SQL query constructed with string interpolation/concatenation.',
      fileExtensions: ['.js', '.ts', '.py', '.php', '.java'],
    },
    {
      name: 'Hardcoded Cryptographic Salt or Weak Hash',
      regex: /\b(createHash\s*\(\s*['"]md5['"]|createHash\s*\(\s*['"]sha1['"])/gi,
      severity: 'MEDIUM',
      description: 'Use of insecure or outdated cryptographic hash algorithm (MD5/SHA1).',
      fileExtensions: ['.js', '.ts', '.py'],
    },
    {
      name: 'Permissive CORS Wildcard',
      regex: /cors\(\s*\{\s*origin\s*:\s*['"]\*['"]/gi,
      severity: 'LOW',
      description: 'Wildcard CORS origin enabled, allowing any external website access.',
      fileExtensions: ['.js', '.ts'],
    },
  ];

  /**
   * 3. Known Vulnerable / Risky NPM Dependencies Audit Table
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

      // Check C: Dependency Audit (package.json)
      if (lower.endsWith('package.json')) {
        this.auditPackageJson(content, file.path, findings);
      }

      // Check D: Secret Scanning inside file
      this.scanSecrets(content, file.path, findings);

      // Check E: SAST Code Analysis
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
          });
          pattern.regex.lastIndex = 0;
        }
      }
    }
  }

  /**
   * Scan code content for SAST security weaknesses
   */
  private static scanStaticAnalysis(content: string, filePath: string, findings: SecurityFinding[]) {
    const lines = content.split('\n');

    for (const pattern of this.SAST_PATTERNS) {
      const matchExt = pattern.fileExtensions.some((ext) => filePath.toLowerCase().endsWith(ext));
      if (!matchExt) continue;

      pattern.regex.lastIndex = 0;
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
          });
          pattern.regex.lastIndex = 0;
        }
      }
    }
  }

  /**
   * Dependency audit for package.json
   */
  private static auditPackageJson(content: string, filePath: string, findings: SecurityFinding[]) {
    try {
      const pkg = JSON.parse(content);
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
          });
        }
      }
    } catch {
      // ignore invalid json parsing
    }
  }
}
