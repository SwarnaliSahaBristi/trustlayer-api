import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

export interface AiExplanationResult {
  explanation: string;
  suggestion: string;
}

@Injectable()
export class AiService {
  private readonly logger = new Logger(AiService.name);
  private readonly geminiApiKey: string | undefined;

  constructor(private readonly config: ConfigService) {
    this.geminiApiKey = this.config.get<string>('GEMINI_API_KEY');
  }

  /**
   * Generates AI explanations and remediation suggestions for a security finding.
   * If GEMINI_API_KEY is configured, calls Google Gemini API.
   * Otherwise falls back gracefully to a curated security heuristics engine.
   */
  async explainFinding(finding: {
    title: string;
    description: string;
    severity: string;
    filePath?: string | null;
    lineNumber?: number | null;
    codeSnippet?: string | null;
  }): Promise<AiExplanationResult> {
    if (this.geminiApiKey) {
      try {
        const geminiResult = await this.callGeminiApi(finding);
        if (geminiResult) return geminiResult;
      } catch (err: any) {
        this.logger.warn(`Gemini API call failed, falling back to heuristics: ${err.message}`);
      }
    }

    return this.generateHeuristicExplanation(finding);
  }

  /**
   * Gemini Generative Language API call
   */
  private async callGeminiApi(finding: any): Promise<AiExplanationResult | null> {
    const prompt = `You are a Senior Security Engineer at TrustLayer. 
Analyze this vulnerability finding:
- Title: ${finding.title}
- Severity: ${finding.severity}
- Description: ${finding.description}
- File Path: ${finding.filePath || 'N/A'}
- Line: ${finding.lineNumber || 'N/A'}
- Code Snippet: ${finding.codeSnippet || 'N/A'}

Respond in JSON format with two keys:
1. "explanation": A concise, clear explanation of why this is dangerous and what an attacker could do.
2. "suggestion": Specific actionable remediation advice or code fix snippet.
Only output valid JSON.`;

    const res = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${this.geminiApiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: { responseMimeType: 'application/json' },
        }),
      },
    );

    if (!res.ok) return null;

    const json = await res.json();
    const rawText = json.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!rawText) return null;

    const parsed = JSON.parse(rawText);
    return {
      explanation: parsed.explanation || '',
      suggestion: parsed.suggestion || '',
    };
  }

  /**
   * High-quality curated security heuristics when external LLM is not configured
   */
  private generateHeuristicExplanation(finding: any): AiExplanationResult {
    const title = (finding.title || '').toLowerCase();

    if (title.includes('aws access key') || title.includes('api key') || title.includes('secret')) {
      return {
        explanation:
          'Hardcoding secrets in source control allows anyone with repository read access (or if leaked publicly) to impersonate your cloud services, exfiltrate data, or incur unauthorized costs.',
        suggestion:
          '1. Immediately rotate the exposed credential in your cloud provider console.\n2. Store secrets in environment variables (.env) or a secret manager (AWS Secrets Manager, HashiCorp Vault).\n3. Add the credential pattern to .gitignore to prevent re-committing.',
      };
    }

    if (title.includes('private key')) {
      return {
        explanation:
          'Committed private keys allow attackers to decrypt confidential traffic, forge authentication tokens, or access servers directly via SSH.',
        suggestion:
          'Revoke and regenerate the key pair immediately. Never commit private keys to git; inject them into deployment pipelines via encrypted CI/CD secrets.',
      };
    }

    if (title.includes('sql injection')) {
      return {
        explanation:
          'String concatenation or direct interpolation in raw SQL queries bypasses parameter binding, enabling attackers to view, modify, or delete the entire database.',
        suggestion:
          'Use parameterized queries or Prisma ORM query builders (e.g. Prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`) instead of unsafe string concatenation.',
      };
    }

    if (title.includes('eval') || title.includes('function')) {
      return {
        explanation:
          'Dynamic code evaluation using eval() runs arbitrary input with full application privileges, enabling Remote Code Execution (RCE) vulnerabilities.',
        suggestion:
          'Refactor the logic to use structured parsers (e.g. JSON.parse for JSON) or static mapping lookup tables instead of eval().',
      };
    }

    if (title.includes('vulnerable dependency')) {
      return {
        explanation:
          'Third-party dependencies with known security advisories expose your application to supply chain attacks, denial of service, or unauthorized access.',
        suggestion:
          'Run `npm audit fix` or update the affected package in package.json to the latest secure patched release.',
      };
    }

    if (title.includes('cors')) {
      return {
        explanation:
          'A wildcard CORS origin (*) permits any malicious site in a user’s browser to read sensitive data if authenticated via cookies or ambient credentials.',
        suggestion:
          'Restrict CORS origin to your specific frontend domain(s) (e.g., origin: ["https://app.trustlayer.io"]).',
      };
    }

    return {
      explanation:
        'This pattern deviates from security best practices and may introduce risk under specific execution conditions.',
      suggestion:
        'Review the flagged code and apply defense-in-depth principles: input validation, least-privilege permissions, and safe API usage.',
    };
  }
}
