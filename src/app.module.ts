import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { GithubModule } from './github/github.module';
import { RepositoriesModule } from './repositories/repositories.module';
import { ScansModule } from './scans/scans.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    PrismaModule,
    AuthModule,
    GithubModule,
    RepositoriesModule,
    ScansModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}