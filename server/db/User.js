const { DataTypes } = require('sequelize');

module.exports = (sequelize) => {
	sequelize.define(
		'user',
		{
			email: {
				type: DataTypes.STRING,
			},
			hashed_password: {
				type: DataTypes.STRING,
			},
			salt: {
				type: DataTypes.STRING,
			},
        },
		{ timestamps: true }
	);
};
