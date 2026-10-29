
import {
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class GithubService {
  constructor(private readonly config: ConfigService) {}

  getAuthorizationUrl(state: string): string {
    const clientId = this.config.get<string>('GITHUB_CLIENT_ID');
    const callbackUrl = this.config.get<string>(
      'GITHUB_CALLBACK_URL',
    );

    if (!clientId || !callbackUrl) {
      throw new InternalServerErrorException(
        'GitHub OAuth configuration is missing',
      );
    }

    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: callbackUrl,
      state,
    });

    return `https://github.com/login/oauth/authorize?${params.toString()}`;
  }

  async exchangeCode(code: string) {
    const clientId = this.config.get<string>('GITHUB_CLIENT_ID');
    const clientSecret = this.config.get<string>(
      'GITHUB_CLIENT_SECRET',
    );
    const callbackUrl = this.config.get<string>(
      'GITHUB_CALLBACK_URL',
    );

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
        'GitHub authorization failed',
      );
    }

    return data.access_token as string;
  }

  async getGithubUser(accessToken: string) {
    const response = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2026-03-10',
      },
    });

    if (!response.ok) {
      throw new InternalServerErrorException(
        'Could not retrieve GitHub profile',
      );
    }

    return response.json();
  }
}
