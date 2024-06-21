import User from '~/models/schemas/User.schema'
import databaseService from './database.services'
import { hashPassword } from '~/utils/crypto'
import { RegisterReqBody } from '~/models/schemas/requests/Users.requests'
import { signToken } from '~/utils/jwt'
import { TokenType } from '~/constants/enums'

class UserService {
  private accessToken(user_id: string) {
    return signToken({ user_id, token_type: TokenType.AccessToken }, { expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN })
  }
  private refreshToken(user_id: string) {
    return signToken(
      { user_id, token_type: TokenType.AccessToken },
      { expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN }
    )
  }
  async register(payload: RegisterReqBody) {
    const result = await databaseService.users.insertOne(
      new User({
        ...payload,
        date_of_birth: new Date(payload.date_of_birth),
        password: hashPassword(payload.password)
      })
    )
    const user_id = result.insertedId.toString()
    const [access_token, refresh_token] = await Promise.all([this.accessToken(user_id), this.refreshToken(user_id)])
    return { access_token, refresh_token }
  }
  async checkEmailExist(email: string) {
    const result = await databaseService.users.findOne({ email })
    return result
  }
}
const usersService = new UserService()
export default usersService
