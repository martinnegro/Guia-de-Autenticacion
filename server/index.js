const { conn } = require('./db');
const app = require('./app');

const port = 3001;

conn
	.sync({ force: true })
	.then(() => {
		app.listen(port, async () => {
			console.log(`Server listening on port: ${port}`);
		});
	})
	.catch((error) => {
		console.log(error);
	});