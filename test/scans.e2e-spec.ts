import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import cookieParser from 'cookie-parser';
import { AppModule } from '../src/app.module';

jest.setTimeout(30000);

describe('Scans API & Status Lifecycle (e2e)', () => {
    let app: INestApplication;
    let accessToken: string;

    beforeAll(async () => {
        const moduleFixture: TestingModule = await Test.createTestingModule({
            imports: [AppModule],
        }).compile();

        app = moduleFixture.createNestApplication();
        app.use(cookieParser());
        app.useGlobalPipes(
            new ValidationPipe({
                whitelist: true,
                transform: true,
            }),
        );
        await app.init();

        // ১. টেস্টের জন্য একজন অথেনটিকেটেড ইউজার তৈরি
        const res = await request(app.getHttpServer())
            .post('/auth/register')
            .send({
                email: `scan_tester_${Date.now()}@example.com`,
                password: 'Password123!',
                name: 'Scan QA',
            });

        accessToken = res.body.accessToken;
    });

    // ১. Security Check - Unauthenticated Access
    it('/scans/recent (GET) - Token ছাড়া 401 Unauthorized দেওয়া উচিত', () => {
        return request(app.getHttpServer())
            .get('/scans/recent')
            .expect(401);
    });

    // ২. Recent Scans - Empty List Check
    it('/scans/recent (GET) - Valid Token দিয়ে সাম্প্রতিক স্ক্যান লিস্ট (খালি এরে) পাওয়া উচিত', () => {
        return request(app.getHttpServer())
            .get('/scans/recent')
            .set('Authorization', `Bearer ${accessToken}`)
            .expect(200)
            .expect((res) => {
                expect(Array.isArray(res.body)).toBe(true);
            });
    });

    // ৩. Scan Trigger - Non-existent Repository (Edge case)
    it('/scans/:repositoryId (POST) - অস্তিত্বহীন রেপো আইডিতে স্ক্যান দিলে 404 Not Found দেওয়া উচিত', () => {
        const fakeRepoId = '11111111-1111-1111-1111-111111111111';
        return request(app.getHttpServer())
            .post(`/scans/${fakeRepoId}`)
            .set('Authorization', `Bearer ${accessToken}`)
            .expect(404);
    });

    // ৪. Scan Status by ID - Non-existent Scan ID (Edge case)
    it('/scans/:scanId (GET) - অস্তিত্বহীন স্ক্যান আইডিতে 404 Not Found দেওয়া উচিত', () => {
        const fakeScanId = '22222222-2222-2222-2222-222222222222';
        return request(app.getHttpServer())
            .get(`/scans/${fakeScanId}`)
            .set('Authorization', `Bearer ${accessToken}`)
            .expect(404);
    });

    // ৫. Finding Status Update - Non-existent Finding ID
    it('/scans/findings/:findingId/status (PATCH) - অস্তিত্বহীন ফাইন্ডিং আপডেট করতে গেলে 404 Not Found দেওয়া উচিত', () => {
        const fakeFindingId = '33333333-3333-3333-3333-333333333333';
        return request(app.getHttpServer())
            .patch(`/scans/findings/${fakeFindingId}/status`)
            .set('Authorization', `Bearer ${accessToken}`)
            .send({ status: 'RESOLVED' })
            .expect(404);
    });

    afterAll(async () => {
        await app.close();
    });
});