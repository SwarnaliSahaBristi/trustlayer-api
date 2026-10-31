import { SecurityEngine } from '../src/scans/security.engine';

describe('SecurityEngine (Unit Test)', () => {
    // ১. Secret Detection Testing
    describe('Secret Detection', () => {
        it('AWS Access Key ডিটেক্ট করতে পারা উচিত', async () => {
            const dummyCode = `
        const AWS = require('aws-sdk');
        const key = "AKIAIOSFODNN7EXAMPLE";
      `;

            const findings = await SecurityEngine.analyzeRepository(
                [{ path: 'src/config.js', sha: '123' }],
                async () => dummyCode,
            );

            expect(findings.length).toBeGreaterThan(0);
            expect(findings[0].title).toBe('AWS Access Key ID');
            expect(findings[0].severity).toBe('CRITICAL');
            expect(findings[0].lineNumber).toBe(3);
        });

        it('GitHub Personal Access Token ডিটেক্ট করতে পারা উচিত', async () => {
            const dummyCode = 'const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12";';

            const findings = await SecurityEngine.analyzeRepository(
                [{ path: 'src/api.js', sha: '123' }],
                async () => dummyCode,
            );

            expect(findings.length).toBeGreaterThan(0);
            expect(findings[0].title).toBe('GitHub Personal Access Token');
            expect(findings[0].severity).toBe('CRITICAL');
        });

        it('Hardcoded Database Credentials ডিটেক্ট করতে পারা উচিত', async () => {
            const dummyCode = 'const dbUri = "postgresql://admin:supersecret@localhost:5432/mydb";';

            const findings = await SecurityEngine.analyzeRepository(
                [{ path: 'database.ts', sha: '123' }],
                async () => dummyCode,
            );

            expect(findings.length).toBeGreaterThan(0);
            expect(findings[0].title).toBe('Database Connection String with Credentials');
            expect(findings[0].severity).toBe('CRITICAL');
        });

        it('কোনো সিক্রেট না থাকলে খালি এরে (empty array) দেওয়া উচিত', async () => {
            const safeCode = 'const name = "TrustLayer"; console.log(name);';

            const findings = await SecurityEngine.analyzeRepository(
                [{ path: 'src/index.ts', sha: '123' }],
                async () => safeCode,
            );

            expect(findings.length).toBe(0);
        });
    });

    // ২. Dependency Vulnerability Testing
    describe('Dependency Vulnerability Detection', () => {
        it('ভালনারেবল প্যাকেজ (e.g. lodash) ডিটেক্ট করতে পারা উচিত', async () => {
            const vulnerablePackageJson = JSON.stringify({
                dependencies: {
                    lodash: '4.17.15',
                },
            });

            const findings = await SecurityEngine.analyzeRepository(
                [{ path: 'package.json', sha: '123' }],
                async () => vulnerablePackageJson,
            );

            expect(findings.length).toBeGreaterThan(0);
            expect(findings[0].title).toContain('lodash');
            expect(findings[0].severity).toBe('MEDIUM');
        });

        it('নিরাপদ ডিপেন্ডেন্সি থাকলে কোনো ভায়োলেশন না ধরা উচিত', async () => {
            const safePackageJson = JSON.stringify({
                dependencies: {
                    express: '^4.19.2',
                },
            });

            const findings = await SecurityEngine.analyzeRepository(
                [{ path: 'package.json', sha: '123' }],
                async () => safePackageJson,
            );

            expect(findings.length).toBe(0);
        });
    });
});