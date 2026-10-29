import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class ScansService {
  private readonly logger = new Logger(ScansService.name);

  constructor(private readonly prisma: PrismaService) {}

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

    // Check if there is already a scan RUNNING or PENDING for this repository
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

    // Start background asynchronous scan execution
    this.processBackgroundScan(scan.id, repository, repository.user.githubConnection.accessToken).catch(
      (err) => {
        this.logger.error(`Background scan failed unexpectedly for scanId ${scan.id}: ${err.message}`, err.stack);
      },
    );

    return {
      message: 'Scan triggered successfully',
      scan,
    };
  }

  /**
   * 2. Background worker processing logic
   */
  private async processBackgroundScan(
    scanId: string,
    repository: { id: string; fullName: string; defaultBranch?: string },
    accessToken: string,
  ) {
    this.logger.log(`Starting scan ${scanId} for ${repository.fullName}`);

    // Update status to RUNNING
    await this.prisma.scan.update({
      where: { id: scanId },
      data: {
        status: 'RUNNING',
        startedAt: new Date(),
      },
    });

    try {
      // Step A: Fetch files tree from GitHub API
      const files = await this.fetchRepositoryFiles(repository.fullName, accessToken);

      // Step B: Security inspections (Secrets, Dependencies, Static Analysis)
      const findings = await this.performSecurityScan(repository.fullName, files, accessToken);

      // Step C: Calculate Risk Score (0-100)
      const riskScore = this.calculateRiskScore(findings);

      // Step D: Save findings into database
      if (findings.length > 0) {
        await this.prisma.finding.createMany({
          data: findings.map((f) => ({
            scanId,
            title: f.title,
            description: f.description,
            severity: f.severity,
            filePath: f.filePath,
            lineNumber: f.lineNumber,
            codeSnippet: f.codeSnippet,
            status: 'OPEN',
          })),
        });
      }

      // Step E: Complete the scan
      await this.prisma.scan.update({
        where: { id: scanId },
        data: {
          status: 'COMPLETED',
          riskScore,
          completedAt: new Date(),
        },
      });

      this.logger.log(`Scan ${scanId} completed with score ${riskScore} and ${findings.length} findings.`);
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
   * Helper: Fetch repository file tree via GitHub Trees API
   */
  private async fetchRepositoryFiles(
    fullName: string,
    accessToken: string,
  ): Promise<Array<{ path: string; type: string; sha: string }>> {
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

    if (!res.ok) {
      // Fallback: If repo is empty or HEAD not found
      return [];
    }

    const data = await res.json();
    return (data.tree || []).filter((item: any) => item.type === 'blob');
  }

  /**
   * Helper: Performs light initial security checks on filenames & high-risk configs
   */
  private async performSecurityScan(
    fullName: string,
    files: Array<{ path: string; type: string; sha: string }>,
    accessToken: string,
  ) {
    const findings: Array<{
      title: string;
      description: string;
      severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
      filePath: string;
      lineNumber?: number;
      codeSnippet?: string;
    }> = [];

    for (const file of files) {
      const lower = file.path.toLowerCase();

      // 1. Secret / Sensitive File Leaks
      if (
        lower.endsWith('.env') ||
        lower.includes('.env.production') ||
        lower.includes('.env.local') ||
        lower.endsWith('.pem') ||
        lower.endsWith('.key') ||
        lower.endsWith('id_rsa')
      ) {
        findings.push({
          title: 'Exposed Sensitive File or Key',
          description: `Sensitive environment or key file '${file.path}' is committed into repository.`,
          severity: 'CRITICAL',
          filePath: file.path,
          lineNumber: 1,
        });
      }

      // 2. Weak Configuration or Docker configs
      if (lower.endsWith('docker-compose.yml') || lower.endsWith('docker-compose.yaml')) {
        findings.push({
          title: 'Docker Compose Configuration Review',
          description: `Ensure passwords, secrets and exposed ports in '${file.path}' are properly managed via secret managers.`,
          severity: 'LOW',
          filePath: file.path,
          lineNumber: 1,
        });
      }

      // Limit deep checks to key config files like package.json or sample configs
      if (file.path === 'package.json') {
        try {
          const contentRes = await fetch(
            `https://api.github.com/repos/${fullName}/contents/${file.path}`,
            {
              headers: {
                Authorization: `Bearer ${accessToken}`,
                Accept: 'application/vnd.github.raw',
              },
            },
          );
          if (contentRes.ok) {
            const text = await contentRes.text();
            if (text.includes('"jsonwebtoken"') && !text.includes('helmet')) {
              findings.push({
                title: 'Missing Security Headers (Helmet)',
                description: 'API uses JWT authentication but does not seem to include Helmet for HTTP security headers.',
                severity: 'MEDIUM',
                filePath: file.path,
              });
            }
          }
        } catch (e) {
          // ignore content fetch error
        }
      }
    }

    return findings;
  }

  /**
   * Calculate Risk Score (0 = Clean, 100 = Critical Danger)
   */
  private calculateRiskScore(findings: Array<{ severity: string }>): number {
    if (findings.length === 0) return 0;

    let score = 0;
    for (const f of findings) {
      if (f.severity === 'CRITICAL') score += 40;
      else if (f.severity === 'HIGH') score += 25;
      else if (f.severity === 'MEDIUM') score += 10;
      else if (f.severity === 'LOW') score += 5;
    }

    return Math.min(score, 100);
  }

  /**
   * 3. Get single scan status and details
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
}
