import { config } from 'dotenv'
import jwt from 'jsonwebtoken'
config()
export const signToken = (payload: string | Buffer | object, options: jwt.SignOptions = { algorithm: 'RS256' }) => {
  return new Promise<string>((resolve, reject) => {
    jwt.sign(payload, process.env.SECRET_KEY as string, options, function (err, token) {
      if (err) throw reject(err)
      resolve(token as string)
    })
  })
}

export const verifyToken = ({
  token,
  secretOrPublicKey = process.env.SECRET_KEY as string
}: {
  token: string
  secretOrPublicKey?: string
}) => {
  return new Promise<jwt.JwtPayload>((resolve, reject) =>
    jwt.verify(token, secretOrPublicKey, (err, decoded) => {
      if (err) {
        throw reject(err)
      }
      console.log(decoded)
      resolve(decoded as jwt.JwtPayload)
    })
  )
}
