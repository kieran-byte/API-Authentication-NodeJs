const jwt = require('jsonwebtoken')

class AuthMethods{

    //middleware
  static async verifyAccessToken(req, res, next){


    console.log('middleware entered')

    //if there are no headers, fail
    if(!req.headers){
      return next(createError.Unauthorized())
    }

    //retrieve token from header
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (!token){
      return next(createError.Unauthorized())
    } 
    
    //if it verifies return the payload
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, payload) => {
      
      if (err) {
        const message =
          err.name === 'JsonWebTokenError' ? 'Unauthorized' : err.message
        return next(createError.Unauthorized(message))
      }
      //put the payload in the req
      req.payload = payload
      next()
    })
  }


}

module.exports = AuthMethods