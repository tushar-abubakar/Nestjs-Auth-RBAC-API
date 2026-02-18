import { Transform } from 'class-transformer';
import {
  IsBoolean,
  IsEmail,
  IsNotEmpty,
  IsOptional,
  IsStrongPassword,
  Length,
  Matches,
  MaxLength,
  MinLength,
  Validate,
  ValidatorConstraint,
  ValidatorConstraintInterface,
} from 'class-validator';
import { i18nValidationMessage } from 'nestjs-i18n';

/**
 * Reserve Username
 */
const RESERVED_USERNAMES = [
  'admin',
  'root',
  'system',
  'support',
  'help',
  'staff',
  'moderator',
  'mod',
  'owner',
  'team',
  'security',
  'api',
  'bot',
  'null',
  'undefined',
  'me',
  'iam',
  'profile',
  'account',
  'settings',
  'login',
  'signup',
  'register',
];

/**
 * Custom transform functions
 */
const trim = ({ value }: { value: unknown }): unknown =>
  typeof value === 'string' ? value.trim() : value;

const trimLower = ({ value }: { value: unknown }): unknown =>
  typeof value === 'string' ? value.trim().toLowerCase() : value;

const normalize = ({ value }: { value: unknown }): unknown => {
  if (typeof value !== 'string') return value;

  return value.trim().normalize('NFKC').toLowerCase();
};

/**
 * Reserved name validator
 */
@ValidatorConstraint({ async: false })
class IsNotReservedUsername implements ValidatorConstraintInterface {
  validate(value: string): boolean {
    if (!value) return true;

    const v = value.toLowerCase();

    if (RESERVED_USERNAMES.includes(v)) return false;

    if (v.startsWith('admin') || v.startsWith('root')) return false;

    return true;
  }

  defaultMessage(): string {
    return 'Username is not available';
  }
}

/**
 * DTO for user registration
 */
export class RegisterDto {
  @Length(2, 100, {
    message: i18nValidationMessage('validation.LENGTH'),
  })
  @IsNotEmpty({
    message: i18nValidationMessage('validation.NOT_EMPTY'),
  })
  @Transform(trim)
  firstName: string;

  @Length(2, 100, {
    message: i18nValidationMessage('validation.LENGTH'),
  })
  @IsNotEmpty({
    message: i18nValidationMessage('validation.NOT_EMPTY'),
  })
  @Transform(trim)
  lastName: string;

  @IsOptional()
  @Validate(IsNotReservedUsername, {
    message: i18nValidationMessage('validation.USERNAME_TAKEN'),
  })
  @Matches(
    /^(?=.{3,30}$)(?![\p{N}._])(?!.*[._]{2})[\p{L}\p{N}._]+(?<![._])$/u,
    {
      message: i18nValidationMessage('validation.USERNAME_FORMAT'),
    },
  )
  @MaxLength(30, {
    message: i18nValidationMessage('validation.MAX_LENGTH'),
  })
  @MinLength(3, {
    message: i18nValidationMessage('validation.MIN_LENGTH'),
  })
  @Transform(normalize)
  username?: string;

  @IsEmail(
    {},
    {
      message: i18nValidationMessage('validation.EMAIL'),
    },
  )
  @MaxLength(128, {
    message: i18nValidationMessage('validation.MAX_LENGTH'),
  })
  @IsNotEmpty({
    message: i18nValidationMessage('validation.NOT_EMPTY'),
  })
  @Transform(trimLower)
  email: string;

  @MaxLength(128, {
    message: i18nValidationMessage('validation.MAX_LENGTH'),
  })
  @IsStrongPassword(
    {
      minLength: 8,
      minLowercase: 1,
      minUppercase: 1,
      minNumbers: 1,
      minSymbols: 1,
    },
    {
      message: i18nValidationMessage('validation.PASSWORD_WEAK'),
    },
  )
  @IsNotEmpty({
    message: i18nValidationMessage('validation.NOT_EMPTY'),
  })
  password: string;
}

/**
 * DTO for login
 */
export class LoginDto {
  @IsNotEmpty({
    message: i18nValidationMessage('validation.NOT_EMPTY'),
  })
  @Transform(trim)
  emailOrUsername: string;

  @IsNotEmpty({
    message: i18nValidationMessage('validation.NOT_EMPTY'),
  })
  password: string;

  @IsOptional()
  @IsBoolean({
    message: i18nValidationMessage('validation.BOOLEAN'),
  })
  remember?: boolean = false;
}

/**
 * DTO for verifying email
 */
export class VerifyEmailDto {
  @Matches(/^\d{6}$/, {
    message: i18nValidationMessage('validation.CODE_INVALID'),
  })
  @IsNotEmpty({
    message: i18nValidationMessage('validation.NOT_EMPTY'),
  })
  @Transform(trim)
  code: string;
}

/**
 * DTO for verifying 2FA
 */
export class Verify2FADto {
  @Matches(/^\d{6}$/, {
    message: i18nValidationMessage('validation.CODE_INVALID'),
  })
  @IsNotEmpty({
    message: i18nValidationMessage('validation.NOT_EMPTY'),
  })
  @Transform(trim)
  code: string;
}

/**
 * DTO for forgot password
 */
export class ForgotPasswordDto {
  @IsNotEmpty({
    message: i18nValidationMessage('validation.NOT_EMPTY'),
  })
  @Transform(trim)
  emailOrUsername: string;
}

/**
 * DTO for verifying reset code
 */
export class VerifyResetCodeDto {
  @Matches(/^\d{6}$/, {
    message: i18nValidationMessage('validation.CODE_INVALID'),
  })
  @IsNotEmpty({
    message: i18nValidationMessage('validation.NOT_EMPTY'),
  })
  @Transform(trim)
  code: string;
}

/**
 * DTO for setting new password
 */
export class SetNewPasswordDto {
  @MaxLength(128, {
    message: i18nValidationMessage('validation.MAX_LENGTH'),
  })
  @IsStrongPassword(
    {
      minLength: 8,
      minLowercase: 1,
      minUppercase: 1,
      minNumbers: 1,
      minSymbols: 1,
    },
    {
      message: i18nValidationMessage('validation.PASSWORD_WEAK'),
    },
  )
  @IsNotEmpty({
    message: i18nValidationMessage('validation.NOT_EMPTY'),
  })
  newPassword: string;

  @IsOptional()
  @IsBoolean({
    message: i18nValidationMessage('validation.BOOLEAN'),
  })
  deleteOtherSessions?: boolean = true;
}

/**
 * DTO for refresh token
 */
export class RefreshTokenDto {
  @IsNotEmpty({
    message: i18nValidationMessage('validation.NOT_EMPTY'),
  })
  @Transform(trim)
  refreshToken: string;
}
