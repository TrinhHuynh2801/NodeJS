import { Router } from 'express'
import {
  RefreshTokenController,
  loginController,
  logoutController,
  registerController
} from '~/controllers/users.controllers'
import {
  registerValidator,
  loginValidator,
  accessTokenValidator,
  refreshTokenValidator
} from '~/middlewares/users.middlewares'
import { wrapRequestHandler } from '../utils/handlers'
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
Get New Refresh Token Request
Body: {refresh_token: string}
*/
usersRouter.post('/refresh-token', refreshTokenValidator, wrapRequestHandler(RefreshTokenController))

export default usersRouter
