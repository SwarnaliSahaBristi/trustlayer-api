import {
  Controller,
  Get,
  Query,
  Req,
  Res,
  BadRequestException,
  UnauthorizedException,
  UseGuards,
  Post,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { randomBytes, timingSafeEqual } from 'crypto';
import { GithubService } from './github.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { GetUser } from '../auth/decorators/get-user.decorator';

const isProduction = process.env.NODE_ENV === 'production';
const STATE_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: isProduction,
  sameSite: (isProduction ? 'none' : 'lax') as 'none' | 'lax',
  maxAge: 10 * 60 * 1000, // 10 minutes
  path: '/',
};

@Controller('github')
export class GithubController {
  constructor(private readonly githubService: GithubService) {}

  /**
   * 1. Initiates GitHub OAuth connect flow.
   * Protected by JwtAuthGuard so we ensure only logged-in TrustLayer users can connect.
   * Saves both state and current user's ID in signed/secure cookies.
   */
  @Get('connect')
  @UseGuards(JwtAuthGuard)
  connect(@GetUser('id') userId: string, @Res() res: Response) {
    const state = randomBytes(32).toString('hex');

    res.cookie('github_oauth_state', state, STATE_COOKIE_OPTIONS);
    res.cookie('github_oauth_user_id', userId, STATE_COOKIE_OPTIONS);

    return res.redirect(this.githubService.getAuthorizationUrl(state));
  }

  /**
   * 2. GitHub OAuth callback.
   * Validates state and retrieves target user ID from secure cookie.
   * Exchanges code for accessToken and stores in GitHubConnection table.
   * Never returns access_token in HTTP response body or URL.
   */
  @Get('callback')
  async callback(
    @Query('code') code: string,
    @Query('state') state: string,
    @Query('error') error: string,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    const savedState = req.cookies?.github_oauth_state;
    const targetUserId = req.cookies?.github_oauth_user_id;

    // Clear state cookies immediately
    res.clearCookie('github_oauth_state', STATE_COOKIE_OPTIONS);
    res.clearCookie('github_oauth_user_id', STATE_COOKIE_OPTIONS);

    if (error) {
      throw new BadRequestException(
        'GitHub authorization was cancelled or denied',
      );
    }

    if (!code || !state || !savedState || !targetUserId) {
      throw new BadRequestException(
        'Missing GitHub authorization parameters or session expired. Please connect again.',
      );
    }

    const received = Buffer.from(state);
    const saved = Buffer.from(savedState);

    if (
      received.length !== saved.length ||
      !timingSafeEqual(received, saved)
    ) {
      throw new UnauthorizedException('Invalid OAuth state');
    }

    // 1. Exchange code for access token (server-side only)
    const accessToken = await this.githubService.exchangeCode(code);

    // 2. Fetch GitHub user profile
    const githubUser = await this.githubService.getGithubUser(accessToken);

    // 3. Link GitHubConnection to TrustLayer User and store token safely in database
    const connection = await this.githubService.saveGitHubConnection(
      targetUserId,
      githubUser,
      accessToken,
    );

    // 4. Return safe payload (ACCESS TOKEN IS NOT EXPOSED TO BROWSER)
    return res.status(200).json({
      message: 'GitHub account linked successfully to TrustLayer',
      connection: {
        connected: connection.connected,
        githubUserId: connection.githubUserId,
        githubLogin: connection.githubLogin,
        avatarUrl: connection.avatarUrl,
      },
    });
  }

  /**
   * 3. Check current user's GitHub connection status.
   */
  @Get('status')
  @UseGuards(JwtAuthGuard)
  async getStatus(@GetUser('id') userId: string) {
    return this.githubService.getConnectionStatus(userId);
  }

  /**
   * 4. Disconnect GitHub account.
   */
  @Post('disconnect')
  @UseGuards(JwtAuthGuard)
  async disconnect(@GetUser('id') userId: string) {
    return this.githubService.disconnect(userId);
  }
}
