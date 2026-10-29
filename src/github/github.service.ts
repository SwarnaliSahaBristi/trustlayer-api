import {
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class GithubService {
  constructor(
    private readonly config: ConfigService,
    private readonly prisma: PrismaService,
  ) {}

  getAuthorizationUrl(state: string): string {
    const clientId = this.config.get<string>('GITHUB_CLIENT_ID');
    const callbackUrl = this.config.get<string>('GITHUB_CALLBACK_URL');

    if (!clientId || !callbackUrl) {
      throw new InternalServerErrorException(
        'GitHub OAuth configuration is missing',
      );
    }

    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: callbackUrl,
      state,
      scope: 'read:user user:email repo',
    });

    return `https://github.com/login/oauth/authorize?${params.toString()}`;
  }

  async exchangeCode(code: string): Promise<string> {
    const clientId = this.config.get<string>('GITHUB_CLIENT_ID');
    const clientSecret = this.config.get<string>('GITHUB_CLIENT_SECRET');
    const callbackUrl = this.config.get<string>('GITHUB_CALLBACK_URL');

    if (!clientId || !clientSecret || !callbackUrl) {
      throw new InternalServerErrorException(
        'GitHub OAuth configuration is missing',
      );
    }

    const response = await fetch(
      'https://github.com/login/oauth/access_token',
      {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          client_id: clientId,
          client_secret: clientSecret,
          code,
          redirect_uri: callbackUrl,
        }),
      },
    );

    const data = await response.json();

    if (!response.ok || data.error || !data.access_token) {
      throw new InternalServerErrorException(
        data.error_description || 'GitHub authorization failed',
      );
    }

    return data.access_token as string;
  }

  async getGithubUser(accessToken: string) {
    const response = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    });

    if (!response.ok) {
      throw new InternalServerErrorException(
        'Could not retrieve GitHub profile',
      );
    }

    return response.json();
  }

  async saveGitHubConnection(
    userId: string,
    githubUser: { id: number | string; login: string; avatar_url?: string },
    accessToken: string,
  ) {
    const githubUserId = String(githubUser.id);

    // Save or update GitHubConnection for the authenticated TrustLayer user
    const connection = await this.prisma.gitHubConnection.upsert({
      where: { userId },
      update: {
        githubUserId,
        accessToken,
      },
      create: {
        userId,
        githubUserId,
        accessToken,
      },
    });

    // Optionally update user's avatar if not set
    if (githubUser.avatar_url) {
      await this.prisma.user.update({
        where: { id: userId },
        data: {
          avatarUrl: githubUser.avatar_url,
        },
      });
    }

    return {
      connected: true,
      githubUserId: connection.githubUserId,
      githubLogin: githubUser.login,
      avatarUrl: githubUser.avatar_url,
    };
  }

  async getConnectionStatus(userId: string) {
    const connection = await this.prisma.gitHubConnection.findUnique({
      where: { userId },
      select: {
        id: true,
        githubUserId: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    return {
      isConnected: !!connection,
      connection,
    };
  }

  async disconnect(userId: string) {
    await this.prisma.gitHubConnection.deleteMany({
      where: { userId },
    });

    return { message: 'GitHub disconnected successfully' };
  }
}
