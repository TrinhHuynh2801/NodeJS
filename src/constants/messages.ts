export const USERS_MESSAGES = {
  VALIDATION_ERROR: 'Validation error',
  NAME_IS_REQUIRED: 'Name is required',
  NAME_IS_STRING: 'Name must be a string',
  NAME_LENGTH_1_TO_100: 'Name is between 1 and 100 characters',
  EMAIL_IS_REQUIRED: 'Email is required',
  EMAIL_IS_INVALID: 'Email is invalid',
  EMAIL_IS_EXIST: 'A user already exists with this email address',
  PASSWORD_IS_REQUIRED: 'Password is required',
  PASSWORD_IS_STRING: 'Password must be a string',
  PASSWORD_LENGTH_6_TO_50: 'Password is between 6 and 50 characters',
  CONFIRM_PASSWORD_IS_REQUIRED: 'Confirm Password is required',
  CONFIRM_PASSWORD_IS_STRING: 'Confirm Password must be a string',
  CONFIRM_PASSWORD_IS_SAME_PASSWORD: 'Password confirmation does not match password',
  DATE_OF_BIRTH_MUST_BE_ISO8601: 'Date of birth must be ISO8601',
  USER_NOT_FOUND: 'Incorret email or password. Or the user is not exist',
  REGISTER_SUCCESS: 'Register Success',
  LOGIN_SUCCESS: 'Login Success'
} as const
