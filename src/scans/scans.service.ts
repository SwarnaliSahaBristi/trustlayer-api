import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { SecurityEngine, SecurityFinding } from './security.engine';
import { AiService } from '../ai/ai.service';
import { EncryptionService } from '../common/encryption.service';

@Injectable()
export class ScansService {
  private readonly logger = new Logger(ScansService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly aiService: AiService,
    private readonly encryption: EncryptionService,
  ) {}

  /**
   * 1. Trigger / Request a new Scan for a repository
   */
  async triggerScan(userId: string, repositoryId: string) {
    const repository = await this.prisma.repository.findFirst({
      where: { id: repositoryId, userId },
      include: {
        user: {
          include: {
            githubConnection: true,
          },
        },
      },
    });

    if (!repository) {
      throw new NotFoundException('Repository not found');
    }

    if (!repository.user.githubConnection?.accessToken) {
      throw new BadRequestException(
        'GitHub account is not connected. Please connect under /github/connect first.',
      );
    }

    // Check for active pending/running scan
    const activeScan = await this.prisma.scan.findFirst({
      where: {
        repositoryId,
        status: { in: ['PENDING', 'RUNNING'] },
      },
    });

    if (activeScan) {
      return {
        message: 'A scan is already in progress for this repository',
        scan: activeScan,
      };
    }

    // Create a new Scan record in PENDING state
    const scan = await this.prisma.scan.create({
      data: {
        repositoryId,
        userId,
        status: 'PENDING',
      },
    });

    // Decrypt access token securely
    const plainAccessToken = this.encryption.decrypt(
      repository.user.githubConnection.accessToken,
    );

    // Start background asynchronous scan
    this.processBackgroundScan(
      scan.id,
      repository,
      plainAccessToken,
    ).catch((err) => {
      this.logger.error(
        `Background scan failed for scanId ${scan.id}: ${err.message}`,
        err.stack,
      );
    });

    return {
      message: 'Scan triggered successfully',
      scan,
    };
  }

  /**
   * 2. Background worker processing logic with SecurityEngine and AI Explanation
   */
  private async processBackgroundScan(
    scanId: string,
    repository: { id: string; fullName: string },
    accessToken: string,
  ) {
    this.logger.log(`Starting scan ${scanId} for ${repository.fullName}`);

    await this.prisma.scan.update({
      where: { id: scanId },
      data: {
        status: 'RUNNING',
        startedAt: new Date(),
      },
    });

    try {
      // Step A: Fetch full file tree from GitHub API
      const files = await this.fetchRepositoryFiles(repository.fullName, accessToken);

      // Step B: Content fetcher closure with error-handling and caching
      const getFileContent = async (path: string): Promise<string | null> => {
        try {
          const res = await fetch(
            `https://api.github.com/repos/${repository.fullName}/contents/${path}`,
            {
              headers: {
                Authorization: `Bearer ${accessToken}`,
                Accept: 'application/vnd.github.raw',
              },
            },
          );
          if (!res.ok) return null;
          return await res.text();
        } catch {
          return null;
        }
      };

      // Step C: Execute SecurityEngine (Secret Detection + Dependency Audit + SAST)
      const findings: SecurityFinding[] = await SecurityEngine.analyzeRepository(
        files,
        getFileContent,
      );

      // Step D: Calculate aggregate Risk Score (0-100)
      const riskScore = this.calculateRiskScore(findings);

      // Step E: Store findings in database with initial heuristic or AI explanations
      for (const f of findings) {
        const aiResult = await this.aiService.explainFinding({
          title: f.title,
          description: f.description,
          severity: f.severity,
          filePath: f.filePath,
          lineNumber: f.lineNumber,
          codeSnippet: f.codeSnippet,
        });

        await this.prisma.finding.create({
          data: {
            scanId,
            title: f.title,
            description: f.description,
            severity: f.severity,
            filePath: f.filePath,
            lineNumber: f.lineNumber,
            codeSnippet: f.codeSnippet,
            aiExplanation: aiResult.explanation,
            aiSuggestion: aiResult.suggestion,
            status: 'OPEN',
          },
        });
      }

      // Step F: Mark scan as COMPLETED
      await this.prisma.scan.update({
        where: { id: scanId },
        data: {
          status: 'COMPLETED',
          riskScore,
          completedAt: new Date(),
        },
      });

      this.logger.log(
        `Scan ${scanId} completed. Risk Score: ${riskScore}, Findings count: ${findings.length}`,
      );
    } catch (error: any) {
      this.logger.error(`Scan ${scanId} failed: ${error.message}`, error.stack);
      await this.prisma.scan.update({
        where: { id: scanId },
        data: {
          status: 'FAILED',
          errorMessage: error.message || 'An error occurred during scan execution',
          completedAt: new Date(),
        },
      });
    }
  }

  /**
   * Helper: Fetch file tree via GitHub API
   */
  private async fetchRepositoryFiles(
    fullName: string,
    accessToken: string,
  ): Promise<Array<{ path: string; sha: string }>> {
    const res = await fetch(
      `https://api.github.com/repos/${fullName}/git/trees/HEAD?recursive=1`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
        },
      },
    );

    if (!res.ok) return [];

    const data = await res.json();
    return (data.tree || [])
      .filter((item: any) => item.type === 'blob')
      .map((item: any) => ({ path: item.path, sha: item.sha }));
  }

  /**
   * Calculate Risk Score (0 = Secure, 100 = Highly Insecure)
   */
  private calculateRiskScore(findings: Array<{ severity: string }>): number {
    if (findings.length === 0) return 0;

    let score = 0;
    for (const f of findings) {
      if (f.severity === 'CRITICAL') score += 35;
      else if (f.severity === 'HIGH') score += 20;
      else if (f.severity === 'MEDIUM') score += 10;
      else if (f.severity === 'LOW') score += 5;
    }

    return Math.min(score, 100);
  }

  /**
   * 3. Get single scan status and all findings
   */
  async getScanById(userId: string, scanId: string) {
    const scan = await this.prisma.scan.findFirst({
      where: { id: scanId, userId },
      include: {
        repository: {
          select: { id: true, name: true, fullName: true, url: true },
        },
        findings: {
          orderBy: { createdAt: 'desc' },
        },
      },
    });

    if (!scan) {
      throw new NotFoundException('Scan not found');
    }

    return scan;
  }

  /**
   * 4. Get all scans for a specific repository
   */
  async getScansByRepository(userId: string, repositoryId: string) {
    const repo = await this.prisma.repository.findFirst({
      where: { id: repositoryId, userId },
    });

    if (!repo) {
      throw new NotFoundException('Repository not found');
    }

    return this.prisma.scan.findMany({
      where: { repositoryId, userId },
      orderBy: { createdAt: 'desc' },
      include: {
        _count: {
          select: { findings: true },
        },
      },
    });
  }

  /**
   * 5. Get recent scans across all repositories for current user
   */
  async getRecentScans(userId: string) {
    return this.prisma.scan.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: 20,
      include: {
        repository: {
          select: { id: true, name: true, fullName: true },
        },
        _count: {
          select: { findings: true },
        },
      },
    });
  }

  /**
   * 6. Update status of a specific finding (e.g. RESOLVED or IGNORED)
   */
  async updateFindingStatus(
    userId: string,
    findingId: string,
    status: 'OPEN' | 'RESOLVED' | 'IGNORED',
  ) {
    const finding = await this.prisma.finding.findFirst({
      where: {
        id: findingId,
        scan: { userId },
      },
    });

    if (!finding) {
      throw new NotFoundException('Finding not found');
    }

    return this.prisma.finding.update({
      where: { id: findingId },
      data: { status },
    });
  }

  /**
   * 7. Trigger on-demand AI explanation for a finding
   */
  async explainFindingOnDemand(userId: string, findingId: string) {
    const finding = await this.prisma.finding.findFirst({
      where: {
        id: findingId,
        scan: { userId },
      },
    });

    if (!finding) {
      throw new NotFoundException('Finding not found');
    }

    const aiResult = await this.aiService.explainFinding(finding);

    return this.prisma.finding.update({
      where: { id: findingId },
      data: {
        aiExplanation: aiResult.explanation,
        aiSuggestion: aiResult.suggestion,
      },
    });
  }
}
