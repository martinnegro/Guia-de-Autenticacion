const crypto = require('crypto');

const withPublicKey = (publicKey, encryptedData) => {
    return crypto.publicDecrypt(publicKey, encryptedData);
};

const withPrivateKey = (privateKey, encryptedData) => {
    return crypto.privateDecrypt(privateKey, encryptedData);
};

module.exports = {  
    withPublicKey,
    withPrivateKey
}