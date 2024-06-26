declare namespace Express {
  export interface Request {
    user: User
    decoded_authorization: TokenPayload
    decoded_refresh_token: TokenPayload
  }
}
