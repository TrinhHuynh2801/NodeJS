import { Request, Response } from 'express'
import { ObjectId } from 'mongodb'
import { USERS_MESSAGES } from '~/constants/messages'
import usersService from '~/services/users.services'

export const loginController = async (req: Request, res: Response) => {
  const user = req.user
  const user_id = user._id as ObjectId
  const result = await usersService.login(user_id.toString())
  res.json({
    message: USERS_MESSAGES.LOGIN_SUCCESS,
    result
  })
}

export const registerController = async (req: Request, res: Response) => {
  const result = await usersService.register(req.body)
  return res.json({
    message: USERS_MESSAGES.REGISTER_SUCCESS,
    result
  })
}

export const logoutController = async (req: Request, res: Response) => {
  const { refresh_token } = req.body
  const result = await usersService.logout(refresh_token)
  return res.json({
    result
  })
}

export const RefreshTokenController = async (req: Request, res: Response) => {
  const { user_id } = req.decoded_refresh_token
  const { refresh_token } = req.body
  const result = await usersService.refreshTokenUpdate(user_id, refresh_token)
  return res.json({
    result
  })
}
