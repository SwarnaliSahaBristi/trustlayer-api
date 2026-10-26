import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { GetUser } from './decorators/get-user.decorator';

const isProduction = process.env.NODE_ENV === 'production';
const REFRESH_COOKIE_NAME = 'refreshToken';
const REFRESH_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: isProduction,
  sameSite: (isProduction ? 'none' : 'lax') as 'none' | 'lax',
  path: '/',
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
};

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(
    @Body() dto: RegisterDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.register(dto);
    this.setRefreshTokenCookie(res, result.refreshToken);

    return {
      message: result.message,
      accessToken: result.accessToken,
      user: result.user,
    };
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() dto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.login(dto);
    this.setRefreshTokenCookie(res, result.refreshToken);

    return {
      message: result.message,
      accessToken: result.accessToken,
      user: result.user,
    };
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const incomingRefreshToken =
      req.cookies?.[REFRESH_COOKIE_NAME] || req.body?.refreshToken;

    const result = await this.authService.refreshTokens(incomingRefreshToken);
    this.setRefreshTokenCookie(res, result.refreshToken);

    return {
      accessToken: result.accessToken,
      user: result.user,
    };
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(
    @GetUser('id') userId: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.logout(userId);
    this.clearRefreshTokenCookie(res);
    return result;
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  getMe(@GetUser() user: any) {
    return {
      user,
    };
  }

  private setRefreshTokenCookie(res: Response, token: string) {
    res.cookie(REFRESH_COOKIE_NAME, token, REFRESH_COOKIE_OPTIONS);
  }

  private clearRefreshTokenCookie(res: Response) {
    res.clearCookie(REFRESH_COOKIE_NAME, {
      ...REFRESH_COOKIE_OPTIONS,
      maxAge: 0,
    });
  }
}
