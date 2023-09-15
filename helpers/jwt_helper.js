const jwt = require('jsonwebtoken')
const createError = require('http-errors')
const client = require('./init_redis')


class TokenController{


  static async signAccessToken(userId) {
    const payload = {};
    const secret = process.env.ACCESS_TOKEN_SECRET;
    const options = {
      expiresIn: '1s',
      issuer: 'pickurpage.com',
      audience: userId,
    };

    try {
      const token = await jwt.sign(payload, secret, options);
      console.log(`token in sign access token is ${token}`)
      return token;
    } catch (err) {
      console.error(err.message);
      // throw createError.InternalServerError();
    }
  }

  static async verifyAccessToken(req, res, next){
    if (!req.headers['authorization']){
      return next(createError.Unauthorized())
    } 
    
    
    const authHeader = req.headers['authorization']
    const bearerToken = authHeader.split(' ')
    const token = bearerToken[1]
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, payload) => {
      
      if (err) {
        const message =
          err.name === 'JsonWebTokenError' ? 'Unauthorized' : err.message
        return next(createError.Unauthorized(message))
      }
      req.payload = payload
      next()
    })
  }


  static async signRefreshToken(userId){
    const payload = {};
    const secret = process.env.REFRESH_TOKEN_SECRET;
    const options = {
      expiresIn: '1y',
      issuer: 'pickurpage.com',
      audience: userId,
    };

    try {
      const token = await jwt.sign(payload, secret, options);

      const expiresInSeconds = 365 * 24 * 60 * 60;

      client.SET(userId, token, 'EX', 365 * 24 * 60 * 60, (err, reply) => {
        if (err) {
          console.log(err.message)
          reject(createError.InternalServerError())
          return
        }
      })

      return token;
    } catch (err) {
      console.error(err.message);
      // throw createError.InternalServerError();
    }
  }

  static async verifyRefreshToken(refreshToken){
    return new Promise((resolve, reject) => {
      jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        (err, payload) => {
          if (err) return reject(createError.Unauthorized())
          const userId = payload.aud
          client.GET(userId, (err, result) => {
            if (err) {
              console.log(err.message)
              reject(createError.InternalServerError())
              return
            }
            if (refreshToken === result) return resolve(userId)
            reject(createError.Unauthorized())
          })
        }
      )
    })
  }
    
}


module.exports = TokenController