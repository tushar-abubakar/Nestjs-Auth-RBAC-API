import { BadRequestException } from '@nestjs/common';
import { ValidationError } from 'class-validator';

type FormattedErrors = Record<string, string[]>;

export const validationExceptionFactory = (
  errors: ValidationError[],
): ValidationException => {
  const result: FormattedErrors = {};

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

  return new ValidationException(result);
};

export class ValidationException extends BadRequestException {
  constructor(public validationErrors: FormattedErrors) {
    super({
      success: false,
      errors: validationErrors,
    });
  }
}
