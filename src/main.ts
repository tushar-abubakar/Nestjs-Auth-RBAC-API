import { ValidationError, ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { I18nValidationExceptionFilter, I18nValidationPipe } from 'nestjs-i18n';
import { AppModule } from './app.module';
import { validationExceptionFactory } from './common/exceptions/validation.exception';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Get ConfigService
  const configService = app.get(ConfigService);

  // Global pipes
  app.useGlobalPipes(
    new I18nValidationPipe({
      whitelist: true,
      transform: true,
      stopAtFirstError: true,
    }),
    new ValidationPipe({
      whitelist: true,
      transform: true,
      exceptionFactory: validationExceptionFactory,
      stopAtFirstError: true,
    }),
  );

  // Global filters
  app.useGlobalFilters(
    new I18nValidationExceptionFilter({
      errorFormatter: (errors: ValidationError[]): Record<string, string[]> => {
        const result: Record<string, string[]> = {};

        const walk = (errs: ValidationError[], parentPath = ''): void => {
          errs.forEach((error: ValidationError) => {
            const path = parentPath
              ? `${parentPath}.${error.property}`
              : error.property;

            if (error.constraints) {
              result[path] = Object.values(error.constraints);
            }

            if (error.children?.length) {
              walk(error.children, path);
            }
          });
        };

        walk(errors);

        return result;
      },
    }),
  );

  // Global logger
  const isProd =
    configService.get<string>('app.env', 'development') === 'production';
  app.useLogger(
    isProd ? ['error', 'warn'] : ['error', 'warn', 'log', 'debug', 'verbose'],
  );

  // CORS
  //app.enableCors();

  const port = configService.get<number>('app.port', 3000);
  await app.listen(port);

  console.log(`Application is running on: http://localhost:${port}`);
}
bootstrap();
