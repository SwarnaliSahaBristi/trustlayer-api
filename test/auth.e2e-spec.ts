import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import cookieParser from 'cookie-parser';
import { AppModule } from '../src/app.module';

jest.setTimeout(30000);

describe('Auth System (e2e)', () => {
  let app: INestApplication;

  // ইউজারের তথ্য ও এক্সেস টোকেন রাখার জন্য ভ্যারিয়েবল
  const testUser = {
    email: `test_${Date.now()}@example.com`,
    password: 'Password123!',
    name: 'Test QA User',
  };
  let accessToken: string;
  let refreshCookie: string;

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

  // ১. রেজিস্টার টেস্ট
  it('/auth/register (POST) - সফলভাবে রেজিস্টার হওয়া উচিত', () => {
    return request(app.getHttpServer())
      .post('/auth/register')
      .send(testUser)
      .expect(201)
      .expect((res) => {
        expect(res.body).toHaveProperty('user');
        expect(res.body.user.email).toBe(testUser.email);
      });
  });

  // ২. সঠিক ডাটা দিয়ে লগইন ও JWT Token সংরক্ষণ
  it('/auth/login (POST) - সঠিক তথ্যে লগইন হয়ে Access Token ও Cookie পাওয়া উচিত', async () => {
    const res = await request(app.getHttpServer())
      .post('/auth/login')
      .send({
        email: testUser.email,
        password: testUser.password,
      })
      .expect(200);

    expect(res.body).toHaveProperty('accessToken');
    accessToken = res.body.accessToken;

    // Refresh Token Cookie চেক করা
    const cookies = res.headers['set-cookie'];
    expect(cookies).toBeDefined();
    refreshCookie = cookies ? cookies[0] : '';
  });

  // ৩. ভুল পাসওয়ার্ডে আটকানো (Edge case)
  it('/auth/login (POST) - ভুল পাসওয়ার্ডে 401 Unauthorized দেওয়া উচিত', () => {
    return request(app.getHttpServer())
      .post('/auth/login')
      .send({
        email: testUser.email,
        password: 'WrongPassword!',
      })
      .expect(401);
  });

  // ৪. JWT Token দিয়ে Protected Route এক্সেস করা
  it('/auth/me (GET) - Valid Token দিয়ে ইউজারের প্রোফাইল পাওয়া উচিত', () => {
    return request(app.getHttpServer())
      .get('/auth/me')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200)
      .expect((res) => {
        expect(res.body.user.email).toBe(testUser.email);
      });
  });

  // ৫. Token ছাড়া Protected Route ব্লক করা (Security check)
  it('/auth/me (GET) - Token না থাকলে 401 Unauthorized দেওয়া উচিত', () => {
    return request(app.getHttpServer())
      .get('/auth/me')
      .expect(401);
  });

  // ৬. Logout টেস্ট
  it('/auth/logout (POST) - লগআউট সফল হওয়া উচিত', () => {
    return request(app.getHttpServer())
      .post('/auth/logout')
      .set('Authorization', `Bearer ${accessToken}`)
      .set('Cookie', refreshCookie)
      .expect(200);
  });

  afterAll(async () => {
    await app.close();
  });
});