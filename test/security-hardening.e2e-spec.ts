import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import helmet from 'helmet';
import { AppModule } from '../src/app.module';

jest.setTimeout(30000);

describe('Security Hardening & Headers (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.use(helmet());
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    );
    await app.init();
  });

  // ১. Helmet Secure Headers Test
  it('Helmet এর সিকিউর HTTP হেডারগুলো রেসপন্সে থাকা উচিত', async () => {
    const res = await request(app.getHttpServer()).get('/auth/login').expect(404); // NestJS returns 404 for unmatched GET on POST route

    // Helmet এর সিকিউরিটি হেডারগুলো ভেরিফাই করা
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBe('SAMEORIGIN');
    expect(res.headers['x-xss-protection']).toBeDefined();
  });

  // ২. Strict Input Sanitization / Mass Assignment Attack Prevention
  it('DTO এর বাইরে কোনো অচেনা/ক্ষতিকর প্রপার্টি পাঠালে 400 Bad Request দিয়ে রিজেক্ট করা উচিত', async () => {
    return request(app.getHttpServer())
      .post('/auth/register')
      .send({
        email: `hacker_${Date.now()}@example.com`,
        password: 'Password123!',
        name: 'Hacker',
        role: 'ADMIN', // চেষ্টা করছে নিজেকে জোর করে ADMIN বানাতে (Mass assignment)
        isAdmin: true,
      })
      .expect(400); // forbidNonWhitelisted নিশ্চিত করছে এটা রিজেক্ট হবে
  });

  afterAll(async () => {
    await app.close();
  });
});

