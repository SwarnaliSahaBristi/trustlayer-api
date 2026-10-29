
import {
  Controller,
  Get,
  Query,
  Req,
  Res,
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { randomBytes, timingSafeEqual } from 'crypto';
import { GithubService } from './github.service';

@Controller('github')
export class GithubController {
  constructor(private readonly githubService: GithubService) {}

  @Get('connect')
  connect(@Res() res: Response) {
    const state = randomBytes(32).toString('hex');

    res.cookie('github_oauth_state', state, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 5 * 60 * 1000,
      path: '/github',
    });

    return res.redirect(
      this.githubService.getAuthorizationUrl(state),
    );
  }

  @Get('callback')
  async callback(
    @Query('code') code: string,
    @Query('state') state: string,
    @Query('error') error: string,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    const savedState = req.cookies?.github_oauth_state;

    res.clearCookie('github_oauth_state', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/github',
    });

    if (error) {
      throw new BadRequestException(
        'GitHub authorization was cancelled or denied',
      );
    }

    if (!code || !state || !savedState) {
      throw new BadRequestException(
        'Missing GitHub authorization parameters',
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

    const accessToken =
      await this.githubService.exchangeCode(code);

    const githubUser =
      await this.githubService.getGithubUser(accessToken);
      
    return res.status(200).json({
      message: 'GitHub authorization successful',
      githubUser: {
        id: githubUser.id,
        login: githubUser.login,
        avatar_url: githubUser.avatar_url,
      },
    });
  }
}
