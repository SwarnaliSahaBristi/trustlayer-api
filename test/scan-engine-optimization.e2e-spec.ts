import { Test, TestingModule } from '@nestjs/testing';
import { Queue } from 'bullmq';
import { ScansService } from '../src/scans/scans.service';
import { PrismaService } from '../src/prisma/prisma.service';
import { AiService } from '../src/ai/ai.service';
import { EncryptionService } from '../src/common/encryption.service';
import { getQueueToken } from '@nestjs/bullmq';

describe('BullMQ Queue & Scan Engine Optimization (Unit Test)', () => {
  let scansService: ScansService;
  let mockQueue: Partial<Queue>;
  let mockPrisma: any;

  beforeAll(async () => {
    mockQueue = {
      add: jest.fn().mockResolvedValue({ id: 'job_123' } as any),
    };

    mockPrisma = {
      repository: {
        findFirst: jest.fn().mockResolvedValue({
          id: 'repo_1',
          userId: 'user_1',
          user: {
            githubConnection: {
              accessToken: 'encrypted_token_123',
            },
          },
        }),
      },
      scan: {
        findFirst: jest.fn().mockResolvedValue(null), // no active scan
        create: jest.fn().mockResolvedValue({
          id: 'scan_123',
          repositoryId: 'repo_1',
          userId: 'user_1',
          status: 'PENDING',
        }),
      },
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ScansService,
        {
          provide: getQueueToken('scan-queue'),
          useValue: mockQueue,
        },
        {
          provide: PrismaService,
          useValue: mockPrisma,
        },
        {
          provide: AiService,
          useValue: { explainFinding: jest.fn() },
        },
        {
          provide: EncryptionService,
          useValue: { decrypt: jest.fn().mockReturnValue('plain_token') },
        },
      ],
    }).compile();

    scansService = module.get<ScansService>(ScansService);
  });

  it('স্ক্যান শুরু হলে সরাসরি ব্যাকগ্রাউন্ডে না চালিয়ে BullMQ কিউতে Retry ও Timeout সহ পুশ করা উচিত', async () => {
    const result = await scansService.triggerScan('user_1', 'repo_1');

    expect(result.message).toContain('queued successfully');
    expect(mockQueue.add).toHaveBeenCalledTimes(1);

    // কিউতে সঠিক কনফিগারেশন পাঠানো হয়েছে কিনা যাচাই
    const [jobName, jobData, jobOptions] = (mockQueue.add as jest.Mock).mock.calls[0];
    expect(jobName).toBe('execute-scan');
    expect(jobData.scanId).toBe('scan_123');
    expect(jobOptions.attempts).toBe(3); // Retry mechanism
  });
});

