import User from '~/models/schemas/User.schema'
import databaseService from './database.services'
import { hashPassword } from '~/utils/crypto'
import { RegisterReqBody } from '~/models/schemas/requests/Users.requests'
import { signToken } from '~/utils/jwt'
import { TokenType, UserVerifyStatus } from '~/constants/enums'
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
  private emailVerifyToken(user_id: string) {
    return signToken(
      { user_id, token_type: TokenType.EmailVerifyToken },
      { expiresIn: process.env.EMAIL_VERIFY_TOKEN_EXPIRES_IN }
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
    const email_verify_token = await this.emailVerifyToken(user_id)
    await databaseService.users.updateOne(
      {
        _id: new ObjectId(user_id)
      },
      { $set: { email_verify_token: email_verify_token } }
    )

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

  async verifyEmail(user_id: string) {
    const [token] = await Promise.all([
      this.signAccessAndRefreshToken(user_id),
      databaseService.users.updateOne(
        { _id: new ObjectId(user_id) },
        {
          $set: {
            email_verify_token: '',
            verify: UserVerifyStatus.Verified,
            updated_at: new Date()
          }
        }
      )
    ])
    const [access_token, refresh_token] = token
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
