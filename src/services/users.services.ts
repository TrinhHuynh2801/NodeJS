import User from '~/models/schemas/User.schema'
import databaseService from './database.services'
import { hashPassword } from '~/utils/crypto'
import { RegisterReqBody, UpdateReqBody } from '~/models/schemas/requests/Users.requests'
import { signToken } from '~/utils/jwt'
import { TokenType, UserVerifyStatus } from '~/constants/enums'
import { RefreshToken } from '~/models/schemas/RefreshToken.schema'
import { ObjectId } from 'mongodb'
import { config } from 'dotenv'
import { USERS_MESSAGES } from '~/constants/messages'
import { ErrorWithStatus } from '~/models/Error'
import HTTP_STATUS from '~/constants/httpStatus'
import Follower from '~/models/schemas/Follower.schema'
config()
class UserService {
  async checkUserExist(email: string, password?: string) {
    const query: { email: string; password?: string } = { email }

    if (password) {
      query.password = password
    }

    const result = await databaseService.users.findOne(query)
    return result
  }
  async findRefreshToken(token: string) {
    const result = await databaseService.refreshTokens.findOne({ token })
    return result
  }

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

  private forgotPasswordToken(user_id: string) {
    return signToken(
      { user_id, token_type: TokenType.ForgotPasswordToken },
      { expiresIn: process.env.PASSWORD_VERIFY_TOKEN_EXPIRES_IN }
    )
  }

  private signAccessAndRefreshToken(user_id: string) {
    return Promise.all([this.accessToken(user_id), this.refreshToken(user_id)])
  }
  async register(payload: RegisterReqBody) {
    const user_id = new ObjectId()
    await databaseService.users.insertOne(
      new User({
        ...payload,
        _id: user_id,
        username: `${payload.name + user_id.toString()}`,
        date_of_birth: new Date(payload.date_of_birth),
        password: hashPassword(payload.password)
      })
    )
    const email_verify_token = await this.emailVerifyToken(user_id.toString())
    await databaseService.users.updateOne(
      {
        _id: new ObjectId(user_id)
      },
      { $set: { email_verify_token: email_verify_token } }
    )

    const [access_token, refresh_token] = await this.signAccessAndRefreshToken(user_id.toString())
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
        { _id: new ObjectId(user_id.trim()) },
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

  async resendVerifyEmail(user_id: string) {
    const email_verify_token = await this.emailVerifyToken(user_id)
    // Gỉa bộ gửi email
    console.log('Rensend verify email: ', email_verify_token)

    // Cập nhật lại giá trị email_verify_token trong document user
    await databaseService.users.updateOne(
      { _id: new ObjectId(user_id.trim()) },
      {
        $set: {
          email_verify_token
        },
        $currentDate: {
          updated_at: true
        }
      }
    )
    return {
      message: USERS_MESSAGES.RESEND_VERIFY_EMAIL_SUCCESS
    }
  }

  async forgotPassword(user_id: string) {
    const forgot_password_token = await this.forgotPasswordToken(user_id)
    // Gỉa bộ gửi email
    console.log('Sending  email: ', forgot_password_token)

    // Cập nhật lại giá trị email_verify_token trong document user
    await databaseService.users.updateOne(
      { _id: new ObjectId(user_id) },
      {
        $set: {
          forgot_password_token
        },
        $currentDate: {
          updated_at: true
        }
      }
    )
    return {
      message: USERS_MESSAGES.CHECK_EMAIL_TO_RESET_PASSWORD
    }
  }

  async resetPassword(id: string, password: string) {
    databaseService.users.updateOne(
      { _id: new ObjectId(id) },
      {
        $set: {
          forgot_password_token: '',
          password: hashPassword(password)
        },
        $currentDate: {
          updated_at: true
        }
      }
    )
    return {
      message: USERS_MESSAGES.RESET_PASSWORD_SUCCESS
    }
  }
  async getMe(user_id: string) {
    const user = await databaseService.users.findOne(
      { _id: new ObjectId(user_id) },
      {
        projection: {
          password: 0,
          email_verify_token: 0,
          forgot_password_token: 0
        }
      }
    )
    return user
  }

  async updateMe(user_id: string, body: UpdateReqBody) {
    const updateBody: { [key: string]: any } = { ...body }

    if (updateBody.date_of_birth) {
      updateBody.date_of_birth = new Date(updateBody.date_of_birth)
    }

    const result = await databaseService.users.findOneAndUpdate(
      {
        _id: new ObjectId(user_id)
      },
      {
        $set: { ...updateBody },
        $currentDate: {
          updated_at: true
        }
      },
      {
        returnDocument: 'after',
        projection: {
          password: 0,
          email_verify_token: 0,
          forgot_password_token: 0
        }
      }
    )
    return result
  }

  async getProfile(username: string) {
    const user = await databaseService.users.findOne(
      { username },
      {
        projection: {
          password: 0,
          email_verify_token: 0,
          forgot_password_token: 0,
          verify: 0,
          created_at: 0,
          updated_at: 0
        }
      }
    )
    if (user === null) {
      return new ErrorWithStatus({
        message: USERS_MESSAGES.USER_NOT_FOUND,
        status: HTTP_STATUS.NOT_FOUND
      })
    }
    return user
  }
  async follow(user_id: string, followed_user_id: string) {
    const follower = await databaseService.followers.findOne({
      user_id: new ObjectId(user_id),
      followed_user_id: new ObjectId(followed_user_id)
    })
    if (follower === null) {
      await databaseService.followers.insertOne(
        new Follower({ user_id: new ObjectId(user_id), followed_user_id: new ObjectId(followed_user_id) })
      )
      return {
        message: USERS_MESSAGES.FOLLOW_SUCCESS
      }
    }
    return {
      message: USERS_MESSAGES.FOLLOWED
    }
  }

  async following(user_id: string) {
    const cursor = databaseService.followers
      .find({ user_id: new ObjectId(user_id) })
      .project({ followed_user_id: 1, _id: 0 })
    const users = await cursor.toArray()
    const followedUserIds = users.map((user) => user.followed_user_id)
    return followedUserIds
  }

  async follower(user_id: string) {
    const cursor = databaseService.followers
      .find({ followed_user_id: new ObjectId(user_id) })
      .project({ user_id: 1, _id: 0 })
    const users = await cursor.toArray()
    const followUserIds = users.map((user) => user.user_id)
    return followUserIds
  }
}
const usersService = new UserService()
export default usersService
