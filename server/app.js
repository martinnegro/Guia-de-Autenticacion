const express = require('express');
const app = express();

const morgan = require('morgan');
const cors = require('cors');

/***** MIDDLEWARES ******/
app.use(morgan('dev'));
app.use(express.json());
app.use(cors());

/***** PASSPORT *********/
const passport = require('passport');
// Importamos la función de nuestro archivo passport.js
// y le pasamos el objeto importado de la librería
require('./passport')(passport)

// Iniciamos passport, requerido para cualquier estrategia
app.use(passport.initialize());

/***** RUTAS ************/
app.use('/',require('./routes'))

module.exports = app;