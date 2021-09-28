const { Router } = require('express');
const router = Router();

const { User } = require('../db');
const { genPassword, validatePassword } = require('./utils');

router.post('/signup', async (req, res) => {
    const { email, password } = req.body;

    try {
        const exists = await User.findOne({ where: { email } })
        if (exists) return res.status(401).send('El usuario ya existe')

        const { genHash, salt } = genPassword(password);
        
        const user = await User.create({
                    email,
                    hashed_password: genHash,
                    salt,
                })
        res.json({
            success: true,
            email: user.email
        })
    } catch(err) { res.sendStatus(500) };
    
});

router.post('/signin', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ where: { email } });
        if (!user) return res.status(401).json({ message: 'El usuario no existe.' })

        const validation = validatePassword(password, user.hashed_password, user.salt)
        if (!validation) return res.status(401).json({ message: 'Password incorrecta.' })

        res.json({
            success: true,
            email: user.email
        })
    } catch(err) { res.sendStatus(500) }

});

module.exports = router;