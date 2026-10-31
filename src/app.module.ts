import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { GithubModule } from './github/github.module';
import { RepositoriesModule } from './repositories/repositories.module';
import { ScansModule } from './scans/scans.module';
import { AiModule } from './ai/ai.module';
import { DashboardModule } from './dashboard/dashboard.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    // 🛡️ Rate Limiting: 60 seconds এ সর্বোচ্চ 100 টি রিকোয়েস্ট (DoS/Brute-force protection)
    ThrottlerModule.forRoot([
      {
        name: 'default',
        ttl: 60000, // 60 seconds in ms
        limit: 100, // max 100 requests per minute
      },
    ]),
    PrismaModule,
    AuthModule,
    GithubModule,
    RepositoriesModule,
    ScansModule,
    AiModule,
    DashboardModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule {}
