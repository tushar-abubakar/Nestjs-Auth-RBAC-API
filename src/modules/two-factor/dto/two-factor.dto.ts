import { Transform } from 'class-transformer';
import { Length } from 'class-validator';
import { i18nValidationMessage } from 'nestjs-i18n';

export class Enable2FADto {
  @Transform(({ value }) => String(value))
  @Length(6, 6, {
    message: i18nValidationMessage('validation.LENGTH'),
  })
  code: string;
}

export class Verify2FADto {
  @Transform(({ value }) => String(value))
  @Length(6, 6, {
    message: i18nValidationMessage('validation.LENGTH'),
  })
  code: string;
}

export class Disable2FADto {
  @Transform(({ value }) => String(value))
  @Length(6, 6, {
    message: i18nValidationMessage('validation.LENGTH'),
  })
  code: string;
}

export class Verify2FAWithBackupDto {
  @Transform(({ value }) => String(value))
  @Length(8, 8, {
    message: i18nValidationMessage('validation.LENGTH'),
  })
  backupCode: string;
}

export class RegenerateBackupCodesDto {
  @Transform(({ value }) => String(value))
  @Length(6, 6, {
    message: i18nValidationMessage('validation.LENGTH'),
  })
  code: string;
}
