import {
  ConflictException,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import * as crypto from 'crypto';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { JwtPayload } from './jwt.strategy';

@Injectable()
export class AuthService {
  private readonly accessSecret =
    process.env.JWT_ACCESS_SECRET ||
    'trustlayer_access_secret_key_2026_super_secure';
  private readonly accessExpiration =
    process.env.JWT_ACCESS_EXPIRATION || '15m';

  private readonly refreshSecret =
    process.env.JWT_REFRESH_SECRET ||
    'trustlayer_refresh_secret_key_2026_ultra_secure';
  private readonly refreshExpiration =
    process.env.JWT_REFRESH_EXPIRATION || '7d';

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async register(dto: RegisterDto) {
    const normalizedEmail = dto.email.trim().toLowerCase();

    const existingUser = await this.prisma.user.findUnique({
      where: { email: normalizedEmail },
    });

    if (existingUser) {
      throw new ConflictException('A user with this email already exists');
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(dto.password, salt);

    const user = await this.prisma.user.create({
      data: {
        email: normalizedEmail,
        password: hashedPassword,
        name: dto.name?.trim(),
      },
      select: {
        id: true,
        email: true,
        name: true,
        avatarUrl: true,
        role: true,
        createdAt: true,
      },
    });

    const tokens = await this.generateTokens(user.id, user.email);
    await this.updateRefreshTokenHash(user.id, tokens.refreshToken);

    return {
      message: 'Registration successful',
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      user,
    };
  }

  async login(dto: LoginDto) {
    const normalizedEmail = dto.email.trim().toLowerCase();

    const user = await this.prisma.user.findUnique({
      where: { email: normalizedEmail },
    });

    if (!user || !user.password) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const isMatch = await bcrypt.compare(dto.password, user.password);
    if (!isMatch) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const tokens = await this.generateTokens(user.id, user.email);
    await this.updateRefreshTokenHash(user.id, tokens.refreshToken);

    return {
      message: 'Login successful',
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        avatarUrl: user.avatarUrl,
        role: user.role,
        createdAt: user.createdAt,
      },
    };
  }

  async refreshTokens(incomingRefreshToken: string) {
    if (!incomingRefreshToken) {
      throw new UnauthorizedException('Refresh token missing');
    }

    let payload: JwtPayload;
    try {
      payload = await this.jwtService.verifyAsync<JwtPayload>(
        incomingRefreshToken,
        {
          secret: this.refreshSecret,
        },
      );
    } catch {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
    });

    if (!user || !user.hashedRefreshToken) {
      throw new ForbiddenException('Access Denied');
    }

    const isTokenMatch = await this.compareToken(
      incomingRefreshToken,
      user.hashedRefreshToken,
    );

    if (!isTokenMatch) {
      // Token reuse detected or invalid token -> clear stored token for security
      await this.prisma.user.update({
        where: { id: user.id },
        data: { hashedRefreshToken: null },
      });
      throw new ForbiddenException('Access Denied: Invalid refresh token');
    }

    // Refresh Token Rotation: issue brand new access & refresh tokens
    const tokens = await this.generateTokens(user.id, user.email);
    await this.updateRefreshTokenHash(user.id, tokens.refreshToken);

    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        avatarUrl: user.avatarUrl,
        role: user.role,
        createdAt: user.createdAt,
      },
    };
  }

  async logout(userId: string) {
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        hashedRefreshToken: { not: null },
      },
      data: {
        hashedRefreshToken: null,
      },
    });

    return {
      message: 'Logged out successfully',
    };
  }

  private async generateTokens(userId: string, email: string) {
    const accessPayload: JwtPayload = { sub: userId, email };
    const refreshPayload: JwtPayload = {
      sub: userId,
      email,
      jti: crypto.randomUUID(),
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(accessPayload, {
        secret: this.accessSecret,
        expiresIn: this.accessExpiration as any,
      }),
      this.jwtService.signAsync(refreshPayload, {
        secret: this.refreshSecret,
        expiresIn: this.refreshExpiration as any,
      }),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }

  private async updateRefreshTokenHash(userId: string, refreshToken: string) {
    const hashed = await this.hashToken(refreshToken);

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        hashedRefreshToken: hashed,
      },
    });
  }

  private hashToken(token: string): Promise<string> {
    const preHash = crypto.createHash('sha256').update(token).digest('hex');
    return bcrypt.hash(preHash, 10);
  }

  private compareToken(token: string, hashedToken: string): Promise<boolean> {
    const preHash = crypto.createHash('sha256').update(token).digest('hex');
    return bcrypt.compare(preHash, hashedToken);
  }
}
