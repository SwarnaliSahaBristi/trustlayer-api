import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';

@Injectable()
export class EncryptionService {
  private readonly algorithm = 'aes-256-gcm';
  private readonly key: Buffer;

  constructor(private readonly config: ConfigService) {
    const secret =
      this.config.get<string>('ENCRYPTION_KEY') ||
      this.config.get<string>('JWT_ACCESS_SECRET') ||
      'trustlayer-default-fallback-secret-2026';

    // Derive a fixed 32-byte (256-bit) key safely using scrypt
    this.key = scryptSync(secret, 'trustlayer-token-salt', 32);
  }

  /**
   * Encrypts plaintext using AES-256-GCM.
   * Returns a compact string in format: iv:authTag:encryptedHex
   */
  encrypt(text: string): string {
    if (!text) return text;
    try {
      const iv = randomBytes(16);
      const cipher = createCipheriv(this.algorithm, this.key, iv);
      let encrypted = cipher.update(text, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      const authTag = cipher.getAuthTag().toString('hex');

      return `${iv.toString('hex')}:${authTag}:${encrypted}`;
    } catch (err: any) {
      throw new InternalServerErrorException(`Token encryption failed: ${err.message}`);
    }
  }

  /**
   * Decrypts an AES-256-GCM payload in format: iv:authTag:encryptedHex.
   * Backwards compatible with legacy plaintext tokens if they were already saved.
   */
  decrypt(cipherPayload: string): string {
    if (!cipherPayload) return cipherPayload;

    const parts = cipherPayload.split(':');
    // If not in encrypted format (3 parts), return legacy plaintext
    if (parts.length !== 3) {
      return cipherPayload;
    }

    try {
      const [ivHex, authTagHex, encryptedHex] = parts;
      const iv = Buffer.from(ivHex, 'hex');
      const authTag = Buffer.from(authTagHex, 'hex');
      const decipher = createDecipheriv(this.algorithm, this.key, iv);
      decipher.setAuthTag(authTag);

      let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    } catch {
      // Fallback to original text if decryption fails (e.g. unencrypted token)
      return cipherPayload;
    }
  }
}

