const crypto = require('crypto');
const fs = require('fs');

const genKeyPair = () => {
    const keyPair =  crypto.generateKeyPairSync('rsa',{ // Algoritmo rsa que genera el par
        modulusLength: 4096, // bits - el estándar para claves rsa
        publicKeyEncoding: {
            type: 'pkcs1', // Public Key Cryptography Standards 1
            format: 'pem'  // Formato de archivo más común
        },
        privateKeyEncoding: {
            type: 'pkcs1', // Public Key Cryptography Standards 1
            format: 'pem'  // Formato de archivo más común
        }
    });

    fs.writeFileSync(__dirname + '/id_rsa_pub.pem', keyPair.publicKey);
    fs.writeFileSync(__dirname + '/id_rsa_priv.pem', keyPair.privateKey);
};

genKeyPair();

