const passport = require('passport');
const { Strategy, ExtractJwt } = require('passport-jwt');
const boom = require('@hapi/boom');

const UsersService = require('../../../services/users');

//Necesario para que la estrategia conozca con que secret fue firmado el jwt y que verifique su validez
const { config } = require('../../../config');

passport.use(
    new Strategy({
        secretOrKey: config.authJwtSecret,
        //Especificamos que el jwt lo vamos a encontrar en el header de Bearer Token luego de haberse hecho una peticion y enviado el jwt
        jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken()
    },
        //funcion de callback que recibe el token payload ya decodificado y una funcion de callback
        async function (tokenPayload, cb) {
            const usersService = new UsersService();

            try {
                const user = await usersService.getUser({ email: tokenPayload.email });

                if (!user) {
                    return cb(boom.unauthorized(), false);
                }

                delete user.password;

                cb(null, { ...user, scopes: tokenPayload.scopes });

            } catch (error) {
                return cb(error);
            }
        })
)