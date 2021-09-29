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