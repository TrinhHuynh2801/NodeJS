import { createHmac } from 'crypto'

export const hashPassword = (password: string) => {
  const sha256 = (string: string) => {
    return createHmac('sha256', process.env.SECRET_KEY as string)
      .update(string)
      .digest('hex')
  }
  return sha256(password)
}
