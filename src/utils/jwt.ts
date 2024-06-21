import jwt from 'jsonwebtoken'

export const signToken = (payload: string | Buffer | object, options: jwt.SignOptions = { algorithm: 'RS256' }) => {
  return new Promise<string>((resolve, reject) => {
    jwt.sign(payload, process.env.SECRET_KEY as string, options, function (err, token) {
      if (err) throw reject(err)
      resolve(token as string)
    })
  })
}
