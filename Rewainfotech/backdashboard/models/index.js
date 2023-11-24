const { Sequelize, DataTypes } = require('sequelize')

const sequelize = new Sequelize('dashboarddb', 'root', 'Neelam@123', {
    host: 'localhost',
    logging: false,
    dialect: 'mysql'
});

try {
    sequelize.authenticate();
    console.log('Connection has been established successfully.');
} catch (error) {
    console.error('Unable to connect to the database:', error);
}

const db = {};
db.Sequelize = Sequelize;
db.sequelize = sequelize;

db.user = require('./user')(sequelize, DataTypes);

db.sequelize.sync({ force: false });

module.exports = db;