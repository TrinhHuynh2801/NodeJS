import User from '~/models/schemas/User.schema'
import databaseService from './database.services'
import { hashPassword } from '~/utils/crypto'
import { RegisterReqBody } from '~/models/schemas/requests/Users.requests'
import { signToken } from '~/utils/jwt'
import { TokenType } from '~/constants/enums'
import { RefreshToken } from '~/models/schemas/RefreshToken.schema'
import { ObjectId } from 'mongodb'
import { config } from 'dotenv'
import { USERS_MESSAGES } from '~/constants/messages'
config()
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
  private signAccessAndRefreshToken(user_id: string) {
    return Promise.all([this.accessToken(user_id), this.refreshToken(user_id)])
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
    const [access_token, refresh_token] = await this.signAccessAndRefreshToken(user_id)
    await databaseService.refreshTokens.insertOne(
      new RefreshToken({ user_id: new ObjectId(user_id), token: refresh_token })
    )
    return { access_token, refresh_token }
  }

  async login(user_id: string) {
    const [access_token, refresh_token] = await this.signAccessAndRefreshToken(user_id)
    await databaseService.refreshTokens.insertOne(
      new RefreshToken({ user_id: new ObjectId(user_id), token: refresh_token })
    )
    return {
      access_token,
      refresh_token
    }
  }
  async logout(refresh_token: string) {
    await databaseService.refreshTokens.deleteOne({ token: refresh_token })
    return {
      message: USERS_MESSAGES.LOGOUT_SUCCESS
    }
  }
  async refreshTokenUpdate(user_id: string, token: string) {
    const [access_token, refresh_token] = await this.signAccessAndRefreshToken(user_id)
    await databaseService.refreshTokens.deleteOne({ token: token })
    await databaseService.refreshTokens.insertOne(
      new RefreshToken({ user_id: new ObjectId(user_id), token: refresh_token })
    )

    return {
      access_token,
      refresh_token
    }
  }

  async checkUserExist(email: string, password?: string) {
    const result = await databaseService.users.findOne({ email, password })
    return result
  }
  async findRefreshToken(token: string) {
    const result = await databaseService.refreshTokens.findOne({ token })
    return result
  }
}
const usersService = new UserService()
export default usersService
