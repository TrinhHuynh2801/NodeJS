import { NextFunction, Request, Response } from 'express'
import usersService from '~/services/users.services'

export const loginController = (req: Request, res: Response) => {
  console.log(req.body)
  res.json({
    message: 'Login Success'
  })
}

export const registerController = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const result = await usersService.register(req.body)
    return res.json({
      message: 'Register success',
      result
    })
  } catch (error) {
    next(error)
  }
}
