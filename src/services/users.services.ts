import User from '~/models/schemas/User.schema'
import databaseService from './database.services'

class UserService {
  async register(payload: { email: string; password: string }) {
    const { email, password } = payload
    const result = await databaseService.users.insertOne(
      new User({
        email,
        password
      })
    )
    return result
  }
  async checkEmailExist(email: string) {
    const result = await databaseService.users.findOne({ email })
    return result
  }
}
const usersService = new UserService()
export default usersService
