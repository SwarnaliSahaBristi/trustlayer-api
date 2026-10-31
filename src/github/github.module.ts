import { Module } from '@nestjs/common';
import { GithubController } from './github.controller';
import { GithubService } from './github.service';
import { EncryptionService } from '../common/encryption.service';

@Module({
  controllers: [GithubController],
  providers: [GithubService, EncryptionService],
  exports: [GithubService, EncryptionService],
})
export class GithubModule {}
