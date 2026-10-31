import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { ImportRepositoryDto } from './dto/import-repository.dto';
import { EncryptionService } from '../common/encryption.service';

@Injectable()
export class RepositoriesService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly encryption: EncryptionService,
  ) {}

  /**
   * 1. Get list of repositories directly from user's connected GitHub account
   */
  async getGitHubRepositories(userId: string) {
    const connection = await this.prisma.gitHubConnection.findUnique({
      where: { userId },
    });

    if (!connection || !connection.accessToken) {
      throw new BadRequestException(
        'Please connect your GitHub account first under /github/connect',
      );
    }

    // 🔒 Decrypt access token securely before calling external GitHub API
    const plainAccessToken = this.encryption.decrypt(connection.accessToken);

    const response = await fetch(
      'https://api.github.com/user/repos?sort=updated&per_page=100',
      {
        headers: {
          Authorization: `Bearer ${plainAccessToken}`,
          Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
        },
      },
    );

    if (!response.ok) {
      throw new BadRequestException('Failed to fetch repositories from GitHub');
    }

    const repos = await response.json();

    // Also get list of already imported repositories by this user for easy UI tracking
    const importedRepos = await this.prisma.repository.findMany({
      where: { userId },
      select: { githubId: true, id: true },
    });

    const importedIds = new Set(importedRepos.map((r) => r.githubId));

    return repos.map((repo: any) => ({
      id: String(repo.id),
      name: repo.name,
      fullName: repo.full_name,
      url: repo.html_url,
      private: repo.private,
      isImported: importedIds.has(String(repo.id)),
      defaultBranch: repo.default_branch,
      description: repo.description,
      language: repo.language,
      updatedAt: repo.updated_at,
    }));
  }

  /**
   * 2. Import a selected repository into TrustLayer database
   */
  async importRepository(userId: string, dto: ImportRepositoryDto) {
    // Check if already imported by this user
    const existing = await this.prisma.repository.findFirst({
      where: {
        userId,
        githubId: dto.githubId,
      },
    });

    if (existing) {
      throw new ConflictException('Repository is already imported');
    }

    const repository = await this.prisma.repository.create({
      data: {
        githubId: dto.githubId,
        name: dto.name,
        fullName: dto.fullName,
        url: dto.url,
        private: dto.private ?? false,
        userId,
      },
    });

    return repository;
  }

  /**
   * 3. Lists all repositories imported in TrustLayer by the authenticated user
   */
  async getUserRepositories(userId: string) {
    return this.prisma.repository.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      include: {
        scans: {
          take: 1,
          orderBy: { createdAt: 'desc' },
          select: {
            id: true,
            status: true,
            riskScore: true,
            createdAt: true,
            _count: {
              select: { findings: true },
            },
          },
        },
      },
    });
  }

  /**
   * 4. Get detailed repository details by ID
   */
  async getRepositoryById(userId: string, repositoryId: string) {
    const repository = await this.prisma.repository.findFirst({
      where: {
        id: repositoryId,
        userId,
      },
      include: {
        scans: {
          orderBy: { createdAt: 'desc' },
          take: 5,
        },
      },
    });

    if (!repository) {
      throw new NotFoundException('Repository not found');
    }

    return repository;
  }

  /**
   * 5. Remove an imported repository
   */
  async deleteRepository(userId: string, repositoryId: string) {
    const repository = await this.prisma.repository.findFirst({
      where: {
        id: repositoryId,
        userId,
      },
    });

    if (!repository) {
      throw new NotFoundException('Repository not found');
    }

    await this.prisma.repository.delete({
      where: { id: repositoryId },
    });

    return { message: 'Repository removed successfully' };
  }
}
