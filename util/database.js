const Sequelize = require('sequelize');

const sequelize = new Sequelize('node-complete', 'root', 'xqwzts', {
  dialect: 'mysql',
  host: 'localhost'
});

module.exports = sequelize;
