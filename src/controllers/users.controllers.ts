import { Request, Response } from 'express'
import usersService from '~/services/users.services'
import crypto, { createHash } from 'crypto'

export const loginController = (req: Request, res: Response) => {
  console.log(req.body)
  res.json({
    message: 'Login Success'
  })
}

export const registerController = async (req: Request, res: Response) => {
  try {
    const result = await usersService.register(req.body)
    return res.json({
      message: 'Register success',
      result
    })
  } catch (error) {
    return res.status(400).json({
      message: 'Register failed',
      error
    })
  }
}
