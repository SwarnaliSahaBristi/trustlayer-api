import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import cookieParser from 'cookie-parser';
import { AppModule } from '../src/app.module';

jest.setTimeout(30000);

describe('GitHub OAuth & Repositories (e2e)', () => {
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

        // ১. টেস্টের জন্য একটি ডামি ইউজার রেজিস্টার ও টোকেন সংগ্রহ
        const res = await request(app.getHttpServer())
            .post('/auth/register')
            .send({
                email: `repo_test_${Date.now()}@example.com`,
                password: 'Password123!',
                name: 'Repo Tester',
            });

        accessToken = res.body.accessToken;
    });

    // ১. GitHub OAuth Connect - Unauthorized Check
    it('/github/connect (GET) - Token ছাড়া 401 Unauthorized দেওয়া উচিত', () => {
        return request(app.getHttpServer())
            .get('/github/connect')
            .expect(401);
    });

    // ২. GitHub OAuth Connect - 302 Redirect & State Cookie Check
    it('/github/connect (GET) - Valid Token দিলে GitHub Login URL-এ redirect এবং Cookie সেট করা উচিত', async () => {
        const res = await request(app.getHttpServer())
            .get('/github/connect')
            .set('Authorization', `Bearer ${accessToken}`)
            .expect(302);

        expect(res.headers.location).toContain('github.com/login/oauth/authorize');
        const cookies = res.headers['set-cookie'];
        expect(cookies).toBeDefined();
        const cookieString = Array.isArray(cookies) ? cookies.join('; ') : String(cookies);
        expect(cookieString).toContain('github_oauth_state');
    });

    // ৩. GitHub OAuth Callback - Invalid State (Edge case / Security attack)
    it('/github/callback (GET) - State মিসম্যাচ হলে 401 Unauthorized হওয়া উচিত', () => {
        return request(app.getHttpServer())
            .get('/github/callback?code=mock_code&state=invalid_state')
            .set('Cookie', 'github_oauth_state=correct_state; github_oauth_user_id=123')
            .expect(401);
    });

    // ৪. Repositories - Protected Route Check
    it('/repositories (GET) - Token ছাড়া 401 Unauthorized দেওয়া উচিত', () => {
        return request(app.getHttpServer())
            .get('/repositories')
            .expect(401);
    });

    // ৫. Repositories - Valid Token দিয়ে খালি রেপো লিস্ট পাওয়া উচিত
    it('/repositories (GET) - Valid Token দিয়ে ইউজারের রেপো লিস্ট (খালি এরে) পাওয়া উচিত', () => {
        return request(app.getHttpServer())
            .get('/repositories')
            .set('Authorization', `Bearer ${accessToken}`)
            .expect(200)
            .expect((res) => {
                expect(Array.isArray(res.body)).toBe(true);
            });
    });

    // ৬. Repository Import - Invalid DTO / Edge Case
    it('/repositories/import (POST) - ভুল ডাটা পাঠালে 400 Bad Request দেওয়া উচিত', () => {
        return request(app.getHttpServer())
            .post('/repositories/import')
            .set('Authorization', `Bearer ${accessToken}`)
            .send({
                // মিসিং 필수 fields (e.g. repo id / name)
                invalidField: 'test',
            })
            .expect(400);
    });

    afterAll(async () => {
        await app.close();
    });
});