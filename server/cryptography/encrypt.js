const crypto = require('crypto');

const withPrivateKey = (privateKey, data) => {
    // Convierte el mensaje en Buffer para poder utilizarlo en el método de crypto
    const bufferData = Buffer.from(data,'utf8');
    return crypto.privateEncrypt(privateKey, bufferData);
};

const withPublicKey = (publicKey, data) => {
    const bufferData = Buffer.from(data,'utf8');
    return crypto.publicEncrypt(publicKey, bufferData);
};

module.exports = {
    withPublicKey,
    withPrivateKey
}