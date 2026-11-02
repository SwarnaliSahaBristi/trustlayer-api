import { Module } from '@nestjs/common';
import { BullModule } from '@nestjs/bullmq';
import { ScansController } from './scans.controller';
import { ScansService } from './scans.service';
import { ScanProcessor } from './scan.processor';
import { AiModule } from '../ai/ai.module';
import { EncryptionService } from '../common/encryption.service';

@Module({
  imports: [
    BullModule.registerQueue({
      name: 'scan-queue',
    }),
    AiModule,
  ],
  controllers: [ScansController],
  providers: [ScansService, EncryptionService, ScanProcessor],
  exports: [ScansService],
})
export class ScansModule {}
