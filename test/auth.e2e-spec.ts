import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import cookieParser from 'cookie-parser';
import { AppModule } from '../src/app.module';

// Jest-এর গ্লোবাল টাইমআউট ৩০ সেকেন্ড দেওয়া হলো (ক্লাউড ডাটাবেজের জন্য)
jest.setTimeout(30000);

describe('Auth System (e2e)', () => {
  let app: INestApplication;

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
  });

  it('/auth/register (POST) - সফলভাবে রেজিস্টার হওয়া উচিত', () => {
    const uniqueEmail = `test_${Date.now()}@example.com`;
    return request(app.getHttpServer())
      .post('/auth/register')
      .send({
        email: uniqueEmail,
        password: 'Password123!',
        name: 'Test User',
      })
      .expect(201)
      .expect((res) => {
        expect(res.body).toHaveProperty('user');
        expect(res.body.user.email).toBe(uniqueEmail);
      });
  });

  it('/auth/login (POST) - ভুল পাসওয়ার্ডে 401 Unauthorized দেওয়া উচিত', () => {
    return request(app.getHttpServer())
      .post('/auth/login')
      .send({
        email: 'nonexistent@example.com',
        password: 'WrongPassword',
      })
      .expect(401);
  });

  afterAll(async () => {
    await app.close();
  });
});