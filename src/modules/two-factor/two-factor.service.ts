import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { hash, verify as verifyHash } from 'argon2';
import { randomBytes } from 'crypto';
import * as QRCode from 'qrcode';
import * as speakeasy from 'speakeasy';

@Injectable()
export class TwoFactorService {
  constructor(private configService: ConfigService) {}

  generateSecret(email: string): { secret: string; otpauth: string } {
    const appName = this.configService.get<string>('app.name', 'AdvancedAuth');

    const secret = speakeasy.generateSecret({
      name: `${appName}:${email}`,
      issuer: appName,
      length: 32,
    });

    return {
      secret: secret.base32,
      otpauth: secret.otpauth_url as string,
    };
  }

  async generateQrCode(otpauthUrl: string): Promise<string> {
    return await QRCode.toDataURL(otpauthUrl);
  }

  verifyToken(token: string, secret: string): boolean {
    return speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: 2,
    });
  }

  async generateBackupCodes(count: number = 10): Promise<{
    plainCodes: string[];
    hashedCodes: string[];
  }> {
    const plainCodes: string[] = [];
    const hashedCodes: string[] = [];

    for (let i = 0; i < count; i++) {
      const code = this.generateBackupCode();
      plainCodes.push(code);
      hashedCodes.push(await hash(code));
    }

    return { plainCodes, hashedCodes };
  }

  private generateBackupCode(): string {
    return randomBytes(4).toString('hex').toUpperCase();
  }

  async verifyBackupCode(
    code: string,
    hashedCodes: string[],
  ): Promise<{ valid: boolean; remainingCodes?: string[] }> {
    for (let i = 0; i < hashedCodes.length; i++) {
      const isValid = await verifyHash(hashedCodes[i], code);
      if (isValid) {
        const remainingCodes = [
          ...hashedCodes.slice(0, i),
          ...hashedCodes.slice(i + 1),
        ];
        return { valid: true, remainingCodes };
      }
    }
    return { valid: false };
  }
}
