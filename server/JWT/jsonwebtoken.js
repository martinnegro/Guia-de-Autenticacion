// npm i jsonwebtoken
const jwt = require('jsonwebtoken');
const fs = require('fs');

const PRIV_KEY = fs.readFileSync(__dirname + '/../cryptography/id_rsa_priv.pem','utf8');
const PUB_KEY  = fs.readFileSync(__dirname + '/../cryptography/id_rsa_pub.pem','utf8');

// Mismo payload que nuestro JWT manual
const payload =  {
    sub: '1',
    name: 'Martin',
    iat: 1516239022
}

// Método para generar el JWT
// No necesitamos escribir el header
// la librería se encarga automáticamente.
const signedJWT = jwt.sign(payload, PRIV_KEY, { algorithm: 'RS256' });

// Método para verificar la validez del token
jwt.verify(signedJWT, PUB_KEY, { algorithm: ['RS256'] },(err, payload)=>{
    console.log(err);
    console.log(payload);
});
