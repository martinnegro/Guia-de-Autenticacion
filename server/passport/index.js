const fs = require('fs');
const passport = require('passport');
const { User } = require('../db');
// Importamos la estrategia
const JwtStrategy = require('passport-jwt').Strategy;
// Y el método para extraer el JWT de la petición
const ExtractJwt = require('passport-jwt').ExtractJwt;

const PUB_KEY =  fs.readFileSync(__dirname + '/../cryptography/id_rsa_pub.pem','utf8');

// Definimos nuestras opciones. Todas las posibilidades
// se encuentran en la documentación de passport-jwt
// y están relacionadas con el uso de jsonwebtoken,
// de donde se debe extraer el token y el algoritmo a utilizar
const options = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: PUB_KEY,
    algorithms: ['RS256']
};

// Creamos una instancia de la estrategia a la que le pasamos nuestras opciones
// y una función callback que se ejecuta si el JWT es válido.
const strategy =  new JwtStrategy(options, (payload, done) => {
    User.findOne({ where: { ID: payload.sub } })
        .then((user)=>{
            if (user) return done(null, user);
            else return done(null, false)
        }).catch((err)=>{ done(err,null) });
});

// Exportamos la función que toma un objeto passport
// y lo devuelve con la estrategia que hemos definido
module.exports = (passport) => {
    passport.use(strategy)
}