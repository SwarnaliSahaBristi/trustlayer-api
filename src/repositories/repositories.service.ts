import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { ImportRepositoryDto } from './dto/import-repository.dto';

@Injectable()
export class RepositoriesService {
  constructor(private readonly prisma: PrismaService) {}

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

    const response = await fetch(
      'https://api.github.com/user/repos?sort=updated&per_page=100',
      {
        headers: {
          Authorization: `Bearer ${connection.accessToken}`,
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

    const importedMap = new Map(
      importedRepos.map((r) => [r.githubId, r.id]),
    );

    return repos.map((repo: any) => ({
      githubId: String(repo.id),
      name: repo.name,
      fullName: repo.full_name,
      url: repo.html_url,
      cloneUrl: repo.clone_url,
      defaultBranch: repo.default_branch,
      private: repo.private,
      description: repo.description,
      language: repo.language,
      isImported: importedMap.has(String(repo.id)),
      importedRepoId: importedMap.get(String(repo.id)) || null,
      updatedAt: repo.updated_at,
    }));
  }

  /**
   * 2. Import a GitHub repository into TrustLayer database
   */
  async importRepository(userId: string, dto: ImportRepositoryDto) {
    const githubId = String(dto.githubId);

    // Check if repo with this githubId already exists
    const existing = await this.prisma.repository.findUnique({
      where: { githubId },
    });

    if (existing) {
      if (existing.userId === userId) {
        return {
          message: 'Repository is already imported',
          repository: existing,
        };
      }
      throw new ConflictException(
        'This repository has already been imported by another user',
      );
    }

    const repository = await this.prisma.repository.create({
      data: {
        githubId,
        name: dto.name,
        fullName: dto.fullName,
        url: dto.url,
        private: dto.private ?? false,
        userId,
      },
    });

    return {
      message: 'Repository imported successfully',
      repository,
    };
  }

  /**
   * 3. Get all repositories imported by the current user in TrustLayer
   */
  async getUserRepositories(userId: string) {
    return this.prisma.repository.findMany({
      where: { userId },
      orderBy: { updatedAt: 'desc' },
      include: {
        _count: {
          select: { scans: true },
        },
      },
    });
  }

  /**
   * 4. Get a single repository details by ID
   */
  async getRepositoryById(userId: string, id: string) {
    const repository = await this.prisma.repository.findFirst({
      where: { id, userId },
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
   * 5. Remove/delete an imported repository
   */
  async deleteRepository(userId: string, id: string) {
    const repo = await this.prisma.repository.findFirst({
      where: { id, userId },
    });

    if (!repo) {
      throw new NotFoundException('Repository not found');
    }

    await this.prisma.repository.delete({
      where: { id },
    });

    return {
      message: 'Repository deleted successfully',
    };
  }
}
