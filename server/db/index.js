require('dotenv').config();

const { Sequelize } = require('sequelize');
const {
	SERVER_DB_USER,
	SERVER_DB_PASS,
	SERVER_DB_HOST,
	SERVER_DB_PORT,
	SERVER_DB_NAME,
} = process.env;

const sequelize = new Sequelize(
	`postgres://${SERVER_DB_USER}:${SERVER_DB_PASS}@${SERVER_DB_HOST}:${SERVER_DB_PORT}/${SERVER_DB_NAME}`,
	{
		logging: false,
		native: false,
	}
);


const models = [];

models.push(require('./User'));

models.forEach((model) => model(sequelize));

let entries = Object.entries(sequelize.models);
let capsEntries = entries.map((entry) => [
  entry[0][0].toUpperCase() + entry[0].slice(1),
  entry[1],
]);
sequelize.models = Object.fromEntries(capsEntries);

module.exports = {
	...sequelize.models,
	conn: sequelize,
};