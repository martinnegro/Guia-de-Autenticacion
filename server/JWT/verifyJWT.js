const base64url = require('base64url');
const crypto = require('crypto');
const fs = require('fs');

// Importamos el JWT
const { JWT } = require('./issueJWT');
// Separamos el JWT en cada una de sus partes
const jwtParts =  JWT.split('.');
const headerInBase64Url    = jwtParts[0];
const payloadInBase64Url   = jwtParts[1];
const signatureInBase64Url = jwtParts[2];

// Generamos una función para verificar nuestro token
// siguiendo un procedimiento similar a cuando creamos el token
const verifyFunction = crypto.createVerify('RSA-SHA256')
verifyFunction.write(headerInBase64Url + '.' + payloadInBase64Url);
verifyFunction.end();
// Debido a que crypto no maneja base64url,
// debemos convertir nuestra firma a base64
const signatureBase64 = base64url.toBase64(signatureInBase64Url);
// Cargamos nuestra clave pública
const PUB_KEY =  fs.readFileSync(__dirname + '/../cryptography/id_rsa_pub.pem','utf8');
// Y realizamos el último paso para verificar la validez de nuestro token
// Si es válido retornará true
// Y si la información fue manipulada de alguna manera, retornará false
const signatureIsValid = verifyFunction.verify(PUB_KEY, signatureBase64, 'base64')

console.log(signatureIsValid);