const createError = require('http-errors')
const User = require('../Models/User.model')
const { authSchema } = require('../helpers/validation_schema')
const {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
} = require('../helpers/jwt_helper')
const client = require('../helpers/init_redis')

class AuthController{

  /**
   * 
   * @param {*} req 
   * @param {*} res 
   */
  static async register(req, res, next){

    try{
      const result = await authSchema.validateAsync(req.body)
      const doesExist = await User.findOne({email: result.email})

      if(doesExist){
        throw createError.Conflict(`${result.email} is already in use`)
      }

      const user = new User(result)
      const savedUser = await user.save()
      const accessToken = await signAccessToken(savedUser.id)
      const refreshToken = await signRefreshToken(savedUser.id)
      res.send({ accessToken, refreshToken })

    }catch(err){
      if (err.isJoi === true){
        err.status = 422
      } 
      next(err)
    }
  }

  /**
   * 
   * @param {*} req 
   * @param {*} res 
   * @returns 
   */
  static async login(req, res, next){
    try {
      const result = await authSchema.validateAsync(req.body)
      
      //if user cannot be found, they are not registered
      const user = await User.findOne({ email: result.email })
      if (!user){
        throw createError.NotFound('User not registered')
      } 
    
      //check if there is a match in the passwords
      const isMatch = await user.isValidPassword(result.password) 
      if (!isMatch){
        throw createError.Unauthorized('Username/password not valid')
      }
      
      //get access and refresh tokens and return them
      const accessToken = await signAccessToken(user.id)
      const refreshToken = await signRefreshToken(user.id)
      res.send({ accessToken, refreshToken })
    } catch (error) {

      if (error.isJoi === true){
        return next(createError.BadRequest('Invalid Username/Password'))
      }
      next(error)
    }
  }

  /**
   * 
   * @param {*} req 
   * @param {*} res 
   * @param {*} next 
   */
  static async refreshToken(req, res, next){
    try {
      //get and check refresh token from body
      const { refreshToken } = req.body
      if (!refreshToken){
        throw createError.BadRequest()
      } 

      //get userId and sign tokens, return
      const userId = await verifyRefreshToken(refreshToken)
      const accessToken = await signAccessToken(userId)
      const refToken = await signRefreshToken(userId)
      res.send({ accessToken: accessToken, refreshToken: refToken })
    } catch (error) {
      next(error)
    }
  }


  static async logout(req, res, next){
    try {
      const { refreshToken } = req.body
      if (!refreshToken) throw createError.BadRequest()
      const userId = await verifyRefreshToken(refreshToken)
      client.DEL(userId, (err, val) => {
        if (err) {
          console.log(err.message)
          throw createError.InternalServerError()
        }
        console.log(val)
        res.sendStatus(204)
      })
    } catch (error) {
      next(error)
    }  
  }
}

module.exports = AuthController

