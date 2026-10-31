import 'dotenv/config';
import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // 🛡️ 1. Helmet: Secure HTTP Response Headers (HSTS, XSS, Sniffing, Clickjacking protection)
  app.use(
    helmet({
      contentSecurityPolicy: process.env.NODE_ENV === 'production' ? undefined : false,
      crossOriginEmbedderPolicy: false,
    }),
  );

  // 🍪 2. Cookie Parser
  app.use(cookieParser());

  // 🌐 3. Strict CORS Configuration
  const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',').map((o) => o.trim())
    : [
        'http://localhost:3000',
        'http://localhost:3001',
        'http://localhost:5173',
      ];

  app.enableCors({
    origin: (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) => {
      // Allow requests with no origin (like mobile apps, curl, Postman, or server-to-server)
      if (!origin || allowedOrigins.includes(origin) || process.env.NODE_ENV !== 'production') {
        callback(null, true);
      } else {
        callback(new Error('Blocked by CORS security policy'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  });

  // 🔍 4. Strict Input Validation & Data Sanitization
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // Strips away any extra unknown malicious fields
      forbidNonWhitelisted: true, // Throws 400 Bad Request if unexpected properties are sent
      transform: true, // Automatically transforms payloads to DTO instances
    }),
  );

  const port = process.env.PORT ?? 3000;
  await app.listen(port);
}
bootstrap();
