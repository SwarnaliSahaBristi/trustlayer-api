import { Module } from '@nestjs/common';
import { ScansController } from './scans.controller';
import { ScansService } from './scans.service';
import { AiModule } from '../ai/ai.module';
import { EncryptionService } from '../common/encryption.service';

@Module({
  imports: [AiModule],
  controllers: [ScansController],
  providers: [ScansService, EncryptionService],
  exports: [ScansService],
})
export class ScansModule {}
