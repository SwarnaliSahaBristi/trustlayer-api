import { Processor, WorkerHost, OnWorkerEvent } from '@nestjs/bullmq';
import { Job } from 'bullmq';
import { Logger } from '@nestjs/common';
import { ScansService } from './scans.service';

export interface ScanJobData {
  scanId: string;
  repositoryId: string;
  userId: string;
}

@Processor('scan-queue', {
  concurrency: 2, // 🔀 Multiple repository scanning: একই সাথে ২টি আলাদা রেপো ব্যাকগ্রাউন্ডে প্রসেস হবে
})
export class ScanProcessor extends WorkerHost {
  private readonly logger = new Logger(ScanProcessor.name);

  constructor(private readonly scansService: ScansService) {
    super();
  }

  async process(job: Job<ScanJobData>): Promise<any> {
    this.logger.log(`Processing scan job ${job.id} for scanId: ${job.data.scanId}`);

    // 📈 Scan progress tracking শুরু: 10%
    await job.updateProgress(10);

    // ScansService এর আসল স্ক্যান লজিক কল করা
    await this.scansService.executeScanJob(job);

    // 📈 Progress tracking সম্পন্ন: 100%
    await job.updateProgress(100);
    return { success: true };
  }

  /**
   * 🛡️ Failed scan recovery: কোনো স্ক্যান যদি আনহ্যান্ডল্ড এররে ফেইল করে
   */
  @OnWorkerEvent('failed')
  async onFailed(job: Job<ScanJobData>, err: Error) {
    this.logger.error(
      `Job ${job.id} failed after ${job.attemptsMade} attempts: ${err.message}`,
      err.stack,
    );
  }
}
