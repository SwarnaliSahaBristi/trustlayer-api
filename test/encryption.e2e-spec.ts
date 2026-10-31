import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { EncryptionService } from '../src/common/encryption.service';

describe('EncryptionService (Unit Test)', () => {
  let service: EncryptionService;

  beforeAll(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        EncryptionService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn().mockReturnValue('super-secret-key-32-chars-long-test!'),
          },
        },
      ],
    }).compile();

    service = module.get<EncryptionService>(EncryptionService);
  });

  it('সফলভাবে প্লেইনটেক্সট এনক্রিপ্ট ও ডিক্রিপ্ট করতে পারা উচিত', () => {
    const originalText = 'ghp_secret_access_token_1234567890';
    const encrypted = service.encrypt(originalText);

    // এনক্রিপ্টেড টেক্সট আসল টেক্সট থেকে আলাদা হতে হবে এবং iv:authTag:data ফরম্যাটে থাকতে হবে
    expect(encrypted).not.toBe(originalText);
    expect(encrypted.split(':').length).toBe(3);

    // ডিক্রিপ্ট করলে আগের টেক্সট ফিরে আসতে হবে
    const decrypted = service.decrypt(encrypted);
    expect(decrypted).toBe(originalText);
  });

  it('লেগ্যাসি বা আন-এনক্রিপ্টেড টোকেন এলেও ক্র্যাশ না করে সেই টেক্সট ফেরত দেওয়া উচিত (Backwards Compatibility)', () => {
    const legacyPlainText = 'ghp_plain_token_without_encryption';
    const result = service.decrypt(legacyPlainText);
    expect(result).toBe(legacyPlainText);
  });
});

