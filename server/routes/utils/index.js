const crypto = require('crypto')

const genPassword = (password) => {
    const salt = crypto.randomBytes(32).toString('hex');
    const genHash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    return {
        salt,
        genHash
    }
};

const validatePassword = (password, hash, salt) => {
    const genHash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
    return hash === genHash;
};


const fs = require('fs');
const jwt = require('jsonwebtoken');

const PRIV_KEY = fs.readFileSync(__dirname + '/../../cryptography/id_rsa_priv.pem')

const issueJWT = (user) => {
    const { ID } = user;
    
    const expiresIn = '1d';
    const payload =  {
        sub: ID,
        iat: Date.now()
    };

    const signedToken = jwt.sign(payload, PRIV_KEY, { expiresIn, algorithm: 'RS256' });

    return {
        token: 'Bearer ' + signedToken,
        expires: expiresIn
    }
};

module.exports = {
    genPassword,
    validatePassword,
    issueJWT
};