const { DataTypes } = require('sequelize');

module.exports = (sequelize) => {
	sequelize.define(
		'user',
		{
			ID: {
				type: DataTypes.INTEGER,
				primaryKey: true,
				autoIncrement: true,
				allowNull: false
			},
			email: {
				type: DataTypes.STRING,
			},
			hashed_password: {
				type: DataTypes.STRING,
			},
			salt: {
				type: DataTypes.STRING,
			},
        }
	);
};
