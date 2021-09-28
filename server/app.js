const express = require('express');
const app = express();
const morgan = require('morgan')

/***** MIDDLEWARES ******/
app.use(morgan('dev'));
app.use(express.json());

/******* RUTAS *******/
app.use('/',require('./routes'))

module.exports = app;