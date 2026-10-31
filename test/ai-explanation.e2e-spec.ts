import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { AiService } from '../src/ai/ai.service';

describe('AI Explanation System (Unit & Fallback Test)', () => {
    let aiService: AiService;

    beforeAll(async () => {
        const moduleRef: TestingModule = await Test.createTestingModule({
            providers: [
                AiService,
                {
                    provide: ConfigService,
                    useValue: {
                        // API Key ছাড়া টেস্ট করছি যাতে আমাদের অফলাইন/ফলব্যাক নিশ্চিত হয়
                        get: jest.fn().mockReturnValue(undefined),
                    },
                },
            ],
        }).compile();

        aiService = moduleRef.get<AiService>(AiService);
    });

    it('সিকিউরিটি ফাইন্ডিংয়ের জন্য explanation এবং suggestion তৈরি করতে পারা উচিত', async () => {
        const mockFinding = {
            title: 'AWS Access Key ID',
            description: 'Potential exposed AWS Access Key ID found in source code.',
            severity: 'CRITICAL',
            filePath: 'src/config.ts',
            lineNumber: 5,
            codeSnippet: 'const awsKey = "AKIAIOSFODNN7EXAMPLE";',
        };

        const result = await aiService.explainFinding(mockFinding);

        expect(result).toBeDefined();
        expect(result).toHaveProperty('explanation');
        expect(result).toHaveProperty('suggestion');
        expect(result.explanation.length).toBeGreaterThan(10);
        expect(result.suggestion.length).toBeGreaterThan(10);
    });

    it('SQL Injection ফাইন্ডিংয়ের জন্যও সঠিক সাজেশন দিতে পারা উচিত', async () => {
        const mockFinding = {
            title: 'SQL Injection Vulnerability (String Concatenation)',
            description: 'Unsafe raw SQL query constructed with string interpolation',
            severity: 'HIGH',
            filePath: 'src/users.service.ts',
            lineNumber: 12,
            codeSnippet: 'SELECT * FROM users WHERE email = ${email}',
        };

        const result = await aiService.explainFinding(mockFinding);

        expect(result.explanation).toBeDefined();
        expect(result.suggestion).toBeDefined();
    });
});