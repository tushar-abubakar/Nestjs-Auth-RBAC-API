# NestJS Auth RBAC API

> Advanced NestJS authentication & authorization system with JWT, RBAC, TOTP 2FA, email verification, rotating refresh tokens, Redis caching, and secure password reset.

[![NestJS](./docs/NestJS-v11.svg)](https://nestjs.com)
[![Prisma](./docs/Prisma-v7.svg)](https://prisma.io)
[![PostgreSQL](./docs/PostgreSQL-18.svg)](https://postgresql.org)
[![TypeScript](./docs/TypeScript-5.svg)](https://typescriptlang.org)
[![License: MIT](./docs/License-MIT.svg)](LICENSE)

---

## Overview

**NestJS Auth RBAC API** is a fully-featured, production-ready authentication and authorization backend built for real-world applications.

It covers the complete auth lifecycle out of the box — registration, email OTP and magic link verification, JWT session management with remember-me, TOTP-based two-factor authentication with backup codes, role-based access control with granular per-endpoint permissions, and a secure multi-step password reset flow. Redis caching, per-user rate limiting, i18n support, and Argon2 password hashing are all included and ready to extend.

Built with NestJS, Prisma, PostgreSQL, and Redis.

---

## Features

| Category | Details |
|---|---|
| JWT Authentication | Access + refresh token rotation, remember-me sessions, device tracking |
| Email Verification | 6-digit OTP + magic link, exponential backoff, daily limits |
| TOTP Two-Factor Auth | Authenticator app support, backup codes, attempt lockout |
| Password Reset | Multi-step: forgot → OTP or magic link → set new password |
| RBAC | Roles (ADMIN, EDITOR, USER) + granular per-endpoint permission guards |
| Session Management | Rotating refresh tokens, user-agent and IP tracking |
| Caching | Redis primary with automatic in-memory fallback |
| Rate Limiting | Per-user, per-IP, per-endpoint counters backed by cache |
| Internationalisation | Full i18n support via `nestjs-i18n` |
| Transactional Email | OTP codes and magic links via Nodemailer |
| Security | Argon2 hashing, anti-enumeration responses, SCAN-safe Redis patterns |

---

## Tech Stack

- **Framework** — NestJS (TypeScript)
- **ORM** — Prisma v7 with PostgreSQL adapter
- **Database** — PostgreSQL 18+
- **Cache** — Redis with in-memory fallback
- **Auth** — Passport.js + `@nestjs/jwt`
- **2FA** — `speakeasy` + `otplib` + QR code generation
- **Password Hashing** — Argon2
- **Email** — Nodemailer + `@nestjs-modules/mailer`
- **Validation** — `class-validator` + `class-transformer`
- **i18n** — `nestjs-i18n`

---

## Project Structure

```
src/
├── common/
│   ├── constants/          # Auth & cache key constants
│   ├── decorators/         # @CurrentUser, @Public, @Permissions, @IpAddress ...
│   ├── exceptions/         # Custom validation exception filter
│   └── types/              # config.type.ts, jwt.type.ts, permission.type.ts
├── config/
│   └── configuration.ts    # Environment config factory
├── cache/
│   ├── cache.service.ts    # Unified Redis/memory interface
│   ├── redis-cache.service.ts
│   └── in-memory-cache.service.ts
├── modules/
│   ├── auth/
│   │   ├── dto/            # RegisterDto, LoginDto, VerifyEmailDto ...
│   │   ├── guards/         # JWT, EmailVerification, PasswordReset, TwoFactor, Permissions
│   │   ├── strategies/     # Passport JWT strategy
│   │   └── auth.service.ts
│   ├── two-factor/         # TOTP setup, enable, disable, backup codes
│   ├── mail/               # Email templates and Nodemailer service
│   ├── role/               # Role management
│   └── permission/         # Permission management + caching
└── prisma/
    └── prisma.service.ts
prisma/
├── schema.prisma
├── seed.ts                 # Roles, permissions & default admin user
└── migrations/
generated/
└── prisma/                 # Prisma-generated client output
postman/
└── nestjs-auth-rbac-api.postman_collection.json
```

---

## Getting Started

### Prerequisites

- Node.js 24+
- PostgreSQL 18+
- Redis *(optional — falls back to in-memory cache)*

### 1. Clone and Install

```bash
git clone https://github.com/YOUR_USERNAME/nestjs-auth-rbac-api.git
cd nestjs-auth-rbac-api
npm install
```

### 2. Configure Environment

```bash
cp .env.example .env
```

Open `.env` and fill in every value marked **REQUIRED**. At minimum:

```env
DATABASE_URL=postgresql://user:password@localhost:5432/nestjs_auth_rbac
JWT_SECRET=<generate: openssl rand -hex 64>
TWO_FACTOR_SECRET=<generate: openssl rand -hex 32>
FRONTEND_URL=http://localhost:8000
```

### 3. Database Setup

```bash
# Run migrations
npx prisma migrate deploy

# Generate Prisma client
npx prisma generate

# Seed roles, permissions, and default admin
npx prisma db seed
```

Default admin credentials after seeding:

```
Email:    admin@example.com
Password: Admin@123
```

### 4. Start the Server

```bash
# Development — watch mode
npm run start:dev

# Production
npm run start:prod
```

Server starts at `http://localhost:4000` by default (configurable via `PORT`).

---

## Authentication Flows

### Registration and Email Verification

```
POST /auth/register
  └── EMAIL_VERIFICATION challenge  (verificationToken)
        ├── POST /auth/email/verify-otp     (manual OTP entry)
        ├── GET  /auth/email/verify-link    (magic link click)
        └── POST /auth/email/resend-otp     (resend OTP)
              └── AUTHENTICATED  (accessToken + refreshToken)
                    └── (if 2FA enabled) TWO_FACTOR_REQUIRED
```

### Login

```
POST /auth/login
  ├── AUTHENTICATED  (accessToken + refreshToken)
  └── TWO_FACTOR_REQUIRED  (twoFactorToken)
        └── POST /auth/two-factor/verify
              └── AUTHENTICATED
```

### Password Reset

```
POST /auth/password/forgot
  └── PASSWORD_RESET_VERIFICATION  (verificationToken)
        ├── POST /auth/password/verify-otp    (OTP path)
        ├── GET  /auth/password/verify-link   (link path)
        └── POST /auth/password/resend-otp    (resend)
              └── PASSWORD_RESET  (resetToken)
                    └── POST /auth/password/reset
                          └── AUTHENTICATED
```

---

## API Reference

### Auth `/auth`

| Method | Endpoint | Guard | Description |
|---|---|---|---|
| POST | `/auth/register` | Public | Create a new account |
| POST | `/auth/login` | Public | Login with email or username + password |
| POST | `/auth/email/verify-otp` | EmailVerification token | Verify email with 6-digit OTP |
| GET | `/auth/email/verify-link` | Query token | Verify email via magic link |
| POST | `/auth/email/resend-otp` | EmailVerification token | Resend verification OTP |
| POST | `/auth/two-factor/verify` | TwoFactor token | Complete 2FA login step |
| POST | `/auth/token/refresh` | Public | Rotate access + refresh tokens |
| POST | `/auth/password/forgot` | Public | Initiate password reset |
| POST | `/auth/password/resend-otp` | PasswordResetVerification token | Resend reset OTP |
| POST | `/auth/password/verify-otp` | PasswordResetVerification token | Verify reset OTP |
| GET | `/auth/password/verify-link` | Query token | Verify reset via magic link |
| POST | `/auth/password/reset` | PasswordReset token | Set new password |

### Two-Factor `/two-factor`

| Method | Endpoint | Permission | Description |
|---|---|---|---|
| GET | `/two-factor/setup` | `2fa:manage` | Get TOTP secret and QR code |
| POST | `/two-factor/enable` | `2fa:manage` | Enable 2FA with TOTP code |
| DELETE | `/two-factor/disable` | `2fa:manage` | Disable 2FA |
| POST | `/two-factor/regenerate-backup-codes` | `2fa:manage` | Generate new backup codes |
| GET | `/two-factor/backup-codes-count` | `2fa:manage` | Remaining backup codes count |
| GET | `/two-factor/status` | `2fa:manage` | 2FA enabled status |

---

## RBAC — Roles and Permissions

### Default Roles

| Role | Description |
|---|---|
| `ADMIN` | Full system access — all permissions granted |
| `EDITOR` | Content and profile management |
| `USER` | Basic profile, session, and 2FA access |

### Permission Reference

Permissions follow the `module:action` pattern:

```
user:read         user:create       user:update       user:delete       user:manage
profile:read      profile:update
session:read      session:delete
admin:access      admin:users:read  admin:users:update admin:users:delete
role:read         role:create       role:update       role:delete
permission:read   permission:assign
2fa:manage
```

Protect any endpoint with the `@Permissions()` decorator:

```typescript
@Get('admin/users')
@Permissions('admin:users:read')
getAllUsers() { ... }
```

---

## Environment Variables

Copy `.env.example` to `.env` and fill in your values.

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | Yes | — | PostgreSQL connection string |
| `JWT_SECRET` | Yes | — | Token signing secret (min 64 chars) |
| `JWT_EXPIRES_IN` | No | `15m` | Access token lifetime |
| `JWT_REFRESH_EXPIRES_IN` | No | `7d` | Refresh token lifetime |
| `JWT_REMEMBER_EXPIRES_IN` | No | `90d` | Remember-me access token lifetime |
| `JWT_REFRESH_REMEMBER_EXPIRES_IN` | No | `60d` | Remember-me refresh token lifetime |
| `JWT_2FA_EXPIRES_IN` | No | `10m` | Challenge token lifetime |
| `FRONTEND_URL` | Yes | — | Base URL for magic links in emails |
| `MAIL_HOST` | Prod | — | SMTP hostname |
| `MAIL_PORT` | Prod | `587` | SMTP port (465 or 587) |
| `MAIL_USER` | Prod | — | SMTP login username |
| `MAIL_PASSWORD` | Prod | — | SMTP login password |
| `MAIL_FROM` | No | auto | From address shown to recipients |
| `REDIS_ENABLED` | No | `false` | Enable Redis cache |
| `REDIS_URL` | No | — | Redis connection URL |
| `TWO_FACTOR_ENABLED` | No | `true` | Enable 2FA system-wide |
| `TWO_FACTOR_SECRET` | Prod | — | TOTP issuer secret (min 32 chars) |
| `CORS_ORIGIN` | No | `http://localhost:3000` | Allowed CORS origin |

See `.env.example` for the full list with descriptions and defaults.

---

## Database Commands

```bash
# Full wipe and fresh start
npx prisma migrate reset --force

# Step-by-step
npx prisma migrate reset --force \
  && npx prisma migrate deploy \
  && npx prisma generate \
  && npx prisma db seed
```

---

## Development Commands

```bash
npm run start:dev       # Start in watch mode
npm run build           # Compile to /dist
npm run lint            # ESLint
npm run test            # Unit tests
npm run test:e2e        # End-to-end tests

npx prisma studio       # Visual database browser
npx prisma format       # Format schema.prisma
```

---

## Postman Collection

A ready-to-import collection covering all 18 endpoints with pre-configured variables and test scripts that auto-save tokens between requests:

```
postman/nestjs-auth-rbac-api.postman_collection.json
```

Import into Postman and run requests top-to-bottom — each response automatically populates `accessToken`, `refreshToken`, `verificationToken`, and other tokens as collection variables.

---

## Contributing

Contributions are welcome. Please open an issue first to discuss what you would like to change, then submit a pull request against the `main` branch.

---

## License

This project is licensed under the [MIT License](LICENSE).