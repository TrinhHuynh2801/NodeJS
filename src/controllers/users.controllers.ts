import { NextFunction, Request, Response } from 'express'
import { ObjectId } from 'mongodb'
import { USERS_MESSAGES } from '~/constants/messages'
import User from '~/models/schemas/User.schema'
import usersService from '~/services/users.services'

export const loginController = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = req.user as User
    const user_id = user._id as ObjectId
    const result = await usersService.login(user_id.toString())
    res.json({
      message: USERS_MESSAGES.LOGIN_SUCCESS,
      result
    })
  } catch (error) {
    next(error)
  }
}

export const registerController = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await usersService.register(req.body)
    return res.json({
      message: USERS_MESSAGES.REGISTER_SUCCESS,
      result
    })
  } catch (error) {
    next(error)
  }
}
