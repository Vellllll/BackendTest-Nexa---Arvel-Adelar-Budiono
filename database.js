const mysql = require('mysql2');

const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'dbnexa',
    socketPath : '/tmp/mysql.sock',
});

module.exports = pool;