const crypto = require('crypto');
const fs = require('fs');
const decrypt = require('./decrypt');

const receivedData = require('./signMessage').packageOfData;

// Cargamos nuestra clave pública.
const publicKey = fs.readFileSync(__dirname + '/id_rsa_pub.pem','utf8');

// Utilizamos el método decrypt que creamos anteriormente
// y le pasamos la clave pública y los datos firmados
const decryptedData = decrypt.withPublicKey(publicKey, receivedData.signedAndEncryptedData);
const decryptedDataHex =  decryptedData.toString();

// Aquí creamos un hash con el mismo algoritmo que nos enviaron.
const hash = crypto.createHash(receivedData.algorithm);

// Tomamos los datos que recibimos sin hashear y los 
// pasamos por la trap door function con el algoritmo
// indicado dentro del paquete de información
const hashOfOriginal = hash.update(JSON.stringify(receivedData.originalData));
const hashOfOriginalHex = hash.digest('hex');

// Si los dos hash son idénticos se imprimirá true 
// y quiere decir que nuestra información es válida
console.log(hashOfOriginalHex === decryptedDataHex) ;


