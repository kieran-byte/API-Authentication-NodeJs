const jwt = require('jsonwebtoken')
const createError = require('http-errors')
const client = require('./init_redis')


class TokenController{


  static signAccessToken(userId) {
    const payload = {};
    const secret = process.env.ACCESS_TOKEN_SECRET;
    const options = {
      expiresIn: '45s',
      issuer: 'pickurpage.com',
      audience: userId,
    };

    try {
      //attemps to sign the jwt and returns if successful 
      const token = jwt.sign(payload, secret, options);
      return token;
    } catch (err) {
      //otherwise throws an error upwards
      console.error(err.message);
      throw createError.InternalServerError();
    }
  }



  static signRefreshToken(userId){
    const payload = {};
    const secret = process.env.REFRESH_TOKEN_SECRET;
    const options = {
      expiresIn: '1y',
      issuer: 'pickurpage.com',
      audience: userId,
    };

    try {
      const token = jwt.sign(payload, secret, options);

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
      //on fail throw upwards
      console.error(err.message);
      throw createError.InternalServerError();
    }
  }

  static verifyRefreshToken(refreshToken){
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