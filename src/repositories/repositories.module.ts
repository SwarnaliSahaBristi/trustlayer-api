import { Module } from '@nestjs/common';
import { RepositoriesController } from './repositories.controller';
import { RepositoriesService } from './repositories.service';
import { EncryptionService } from '../common/encryption.service';

@Module({
  controllers: [RepositoriesController],
  providers: [RepositoriesService, EncryptionService],
  exports: [RepositoriesService],
})
export class RepositoriesModule {}
