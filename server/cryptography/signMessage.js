const crypto = require('crypto');
const fs = require('fs');
const encrypt = require('./encrypt');

// Ejemplo de datos de usuario que quisieramos transportar en nuestros tokens
const myData =  {
    email: 'martin@email.com',
    name: 'martin'
}

// Trap Door Function
const hash = crypto.createHash('sha256')
// Necesitamos nuestros datos en formato string para poder hashearlos
const myDataString = JSON.stringify(myData)
// Combinamos nuestra función hash con nuestros datos
hash.update(myDataString);
// Convertimos nuestros datos hasheados a formato hexadecimal
const hashedData = hash.digest('hex');

/****  Ahora pasamos a la FIRMA DIGITAL ****/
// Cargamos nuestra clave privada
const privateKey = fs.readFileSync(__dirname + '/id_rsa_priv.pem', 'utf8')

// Creamos un objeto Buffer con nuestro mensaje y la clave privada
// Es decir, firmamos nuestros datos
const signedData = encrypt.withPrivateKey(privateKey, hashedData) // Utilizamos el método que creamos anteriormente

// INFORMACIÓN ADICIONAL QUE ENVIAMOS PARA PODER VERIFICAR IDENTIDAD
const packageOfData = {
    algorithm: 'sha256',
    originalData: myData,
    signedAndEncryptedData: signedData
}

module.exports = {
    packageOfData
}