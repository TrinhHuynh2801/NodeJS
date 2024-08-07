import { Router } from 'express'
import {
  changePasswordController,
  emailVerifyTokenController,
  followController,
  followerController,
  followingController,
  forgotPasswordController,
  getMeController,
  getProfileController,
  loginController,
  logoutController,
  refreshTokenController,
  registerController,
  resendVerifyEmailController,
  resetPasswordController,
  unfollowController,
  updateMeController
} from '~/controllers/users.controllers'
import {
  registerValidator,
  loginValidator,
  accessTokenValidator,
  refreshTokenValidator,
  emailVerifyTokenValidator,
  forgotPasswordValidator,
  resetPasswordValidator,
  verifiedUserValidator,
  updateMeValidator,
  filterUpdateReqValidator,
  followingValidator,
  followerValidator,
  changePasswordValidator
} from '~/middlewares/users.middlewares'
import { wrapRequestHandler } from '../utils/handlers'
import { UpdateReqBody } from '~/models/schemas/requests/Users.requests'
const usersRouter = Router()
/*
Login Request
Body {email, password}
*/
usersRouter.post('/login', loginValidator, wrapRequestHandler(loginController))

/*
Register Request
Body 
  name: string
  email: string
  password: string
  confirm_password: string
  date_of_birth: string
*/
usersRouter.post('/register', registerValidator, wrapRequestHandler(registerController))

/*
Logout Request
Header: {Authorization: Bearer <access_token>}
Body: {refresh_token: string}
*/
usersRouter.post('/logout', accessTokenValidator, refreshTokenValidator, wrapRequestHandler(logoutController))

/*
New Refresh Token Request
Body: {refresh_token: string}
*/
usersRouter.post('/refresh-token', refreshTokenValidator, wrapRequestHandler(refreshTokenController))

/**
 * Description. Verify email when user client click on the link in email
 * Path: /verify-email
 * Method: POST
 * Body: { email_verify_token: string }
 */
usersRouter.post('/verify-email', emailVerifyTokenValidator, wrapRequestHandler(emailVerifyTokenController))

/**
 * Description. Verify email when user client click on the link in email
 * Path: /resend-verify-email
 * Method: POST
 * Header: { Authorization: Bearer <access_token> }
 * Body: {}
 */
usersRouter.post('/resend-verify-email', accessTokenValidator, wrapRequestHandler(resendVerifyEmailController))

/**
 * Description. Forgot password
 * Path: /forgot-password
 * Method: POST
 * Body: {email: string}
 */
usersRouter.post('/forgot-password', forgotPasswordValidator, wrapRequestHandler(forgotPasswordController))

/**
 * Description. Reset password
 * Path: /reset-password
 * Method: POST
 * Body: {password:string, confirm-password:string, forgot_password_token: string}
 */
usersRouter.post('/reset-password', resetPasswordValidator, wrapRequestHandler(resetPasswordController))

/**
 * Description: Get my profile
 * Path: /me
 * Method: GET
 * Header: { Authorization: Bearer <access_token> }
 */
usersRouter.get('/me', accessTokenValidator, wrapRequestHandler(getMeController))

/**
 * Description: Update my profile
 * Path: /me
 * Method: PATCH
 * Header: { Authorization: Bearer <access_token> }
 * Body: UserSchema
 */
usersRouter.put(
  '/me',
  accessTokenValidator,
  verifiedUserValidator,
  filterUpdateReqValidator<UpdateReqBody>([
    'name',
    'date_of_birth',
    'bio',
    'location',
    'website',
    'avatar',
    'cover_photo',
    'username'
  ]),
  updateMeValidator,
  wrapRequestHandler(updateMeController)
)

/**
 * Description: User follow another user
 * Path: /follow
 * Method: POST
 * Header: { Authorization: Bearer <access_token> }
 * Body: followed_user_id
 */
usersRouter.post('/follow', accessTokenValidator, wrapRequestHandler(followController))

/**
 * Description: User unfollow another user
 * Path: /follow
 * Method: DELETE
 * Header: { Authorization: Bearer <access_token> }
 * Body: followed_user_id
 */
usersRouter.delete('/follow', accessTokenValidator, wrapRequestHandler(unfollowController))

/**
 * Description: List of users someone following
 * Path: /following
 * Method: GET
 * Body: user_id
 */
usersRouter.get('/following', followingValidator, wrapRequestHandler(followingController))

/**
 * Description: List of users following a user
 * Path: /followers
 * Method: GET
 * Body: followed_user_id
 */
usersRouter.get('/followers', followerValidator, wrapRequestHandler(followerController))

/**
 * Description: Change password
 * Path: /change-password
 * Method: PUT
 * Header: { Authorization: Bearer <access_token> }
 * Body: { old_password: string, password: string, confirm_password: string }
 */
usersRouter.put(
  '/change-password',
  accessTokenValidator,
  verifiedUserValidator,
  changePasswordValidator,
  wrapRequestHandler(changePasswordController)
)

/**
 * Description: Get user profile
 * Path: /:username
 * Method: GET
 */
usersRouter.get('/:username', wrapRequestHandler(getProfileController))
export default usersRouter
