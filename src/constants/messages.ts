export const USERS_MESSAGES = {
  VALIDATION_ERROR: 'Validation error',
  NAME_IS_REQUIRED: 'Name is required',
  NAME_IS_STRING: 'Name must be a string',
  NAME_LENGTH_1_TO_100: 'Name is between 1 and 100 characters',
  EMAIL_IS_REQUIRED: 'Email is required',
  EMAIL_IS_INVALID: 'Email is invalid',
  EMAIL_IS_EXIST: 'A user already exists with this email address',
  EMAIL_IS_NOT_EXIST: 'User is not exist',
  PASSWORD_IS_REQUIRED: 'Password is required',
  PASSWORD_IS_STRING: 'Password must be a string',
  PASSWORD_LENGTH_6_TO_50: 'Password is between 6 and 50 characters',
  CONFIRM_PASSWORD_IS_REQUIRED: 'Confirm Password is required',
  CONFIRM_PASSWORD_IS_STRING: 'Confirm Password must be a string',
  CONFIRM_PASSWORD_IS_SAME_PASSWORD: 'Password confirmation does not match password',
  DATE_OF_BIRTH_MUST_BE_ISO8601: 'Date of birth must be ISO8601',
  INCORRECT_INFO: 'Incorrect email or password.',
  USER_NOT_FOUND: 'The user is not exist',
  REGISTER_SUCCESS: 'Register Success',
  LOGIN_SUCCESS: 'Login Success',
  LOGOUT_SUCCESS: 'Logout Success',
  ACCESS_TOKEN_IS_REQUIRED: 'Access token is required',
  REFRESH_TOKEN_IS_REQUIRED: 'Refresh token is required',
  USED_REFRESH_TOKEN_OR_NOT_EXIST: 'Used refresh token or not exist',
  EMAIL_VERIFY_TOKEN_IS_REQUIRED: 'Email verify token is required',
  EMAIL_ALREADY_VERIFIED_BEFORE: 'Email already verified before',
  EMAIL_VERIFY_SUCCESS: 'Email verify success',
  RESEND_VERIFY_EMAIL_SUCCESS: 'Resend verify email success',
  CHECK_EMAIL_TO_RESET_PASSWORD: 'Check email to reset password'
} as const
