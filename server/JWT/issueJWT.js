// npm i base64url
const base64url = require('base64url');
const crypto = require('crypto');
const fs = require('fs');

// Queremos generar un JWT con esta información
const header = {
    alg: 'RS256',
    type: 'JWT'
}
const payload =  {
    sub: '1',
    name: 'Martin',
    iat: 1516239022
}
// Primero debemos convertir los objetos a formato string
// para poder trabajar con ellos
const headerString = JSON.stringify(header);
const payloadString = JSON.stringify(payload);
// La información sigue en formato json
// por lo que ahora debemos codificar en formato base64url
const headerBase64url = base64url(headerString);
const payloadBase64url = base64url(payloadString);
// El siguiente paso es generar un hash con esos dos datos
// y luego firmarlo.
// Creamos una función de firma con el algoritmo especificado
const signatureFunction = crypto.createSign('RSA-SHA256');
// Pasamos nuestra información para generar el primer hash
signatureFunction.write(headerBase64url + '.' + payloadBase64url);
signatureFunction.end()
// Luego cargamos nuestra clave privada
const PRIV_KEY =  fs.readFileSync(__dirname + '/../cryptography/id_rsa_priv.pem','utf8');
// Y generamos la firma de nuestro JWT
const signatureBase64 = signatureFunction.sign(PRIV_KEY, 'base64');
// Convertimos el encoding de nuestra
// firma de base64 a base64url
const signatureBase64url = base64url.fromBase64(signatureBase64);
// Y por último juntamos las piezas para armar nuestro JWT
const JWT = headerBase64url + '.' + payloadBase64url + '.' + signatureBase64url;

// Simulamos el envío del JWT
module.exports = {
    JWT
}



// const JWT = 'eyJhbGciOiJSUzI1NiIsInR5cGUiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.F4SZ0OyVkxsZvQS_Gw3AFKUz7VVKGhjfkKB0xIkymwLbNyUgSVVeBZFiAQyZQjUeuS-4gLPGwCJ4xj_HQsLsJllKejMlUg3oh0WnI0Z07FEqum4opVPNCMj1xKXMW3ioSxJfbMkSpJTeVZPdZgRCpp_LjKpg3sfdOl3_bnlsMILmRlqMuYsM9Qdm5-6v_WiJzGDMnLYs2WpyyXwqaPk7EoQWAU';

// // Dividimos el JWT en cada una de sus partes
// const JWTParts = JWT.split('.');
// // Y los guardamos en distintas constantes
// const headerInBase64Url    = JWTParts[0];
// const payloadInBase64Url   = JWTParts[1];
// const signatureInBase64Url = JWTParts[2];

// // Decodificamos las partes con la librería base64url
// const decodeHeader    = base64url.decode(headerInBase64Url); 
// const decodePayload   = base64url.decode(payloadInBase64Url); 
// const decodeSignature = base64url.decode(signatureInBase64Url); 

// console.log(decodeHeader);
// console.log(decodePayload);
// console.log(decodeSignature);