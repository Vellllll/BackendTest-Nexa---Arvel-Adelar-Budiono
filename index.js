const express = require('express')
const app = express()
const port = 3000
const dotenv = require('dotenv');
const pool = require('./database');
const CryptoJS = require("crypto-js");
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const moment = require('moment');

dotenv.config();

app.use(bodyParser.json());

app.get('/', (req, res) => {
  res.send('Hello World!')
})

app.post('/api/login', (request, response) => {
    const { username, password } = request.body;
    if (username && password) {
        pool.query(`SELECT id, username, password FROM admin WHERE username = '${username}'`, (error, result) => {
            if (error == null) {
                if (result.length > 0) {
                    const decryptedPassword = CryptoJS.AES.decrypt(result[0].password.toString(), process.env.SECRET_KEY).toString(CryptoJS.enc.Utf8);
                    if (decryptedPassword == password) {
                        const currentDt = moment().utc().format('YYYY-MM-DD HH:mm:ss');
                        const token = jwt.sign({
                            'username': username,
                            'password': password,
                            'currentDt': currentDt
                        }, process.env.SECRET_KEY, { expiresIn: '3600s' });

                        const tokenExpiredDt = moment(currentDt).add(3600, 'seconds').format('YYYY-MM-DD HH:mm:ss');

                        pool.query(`INSERT INTO admin_token (id_admin, token, expired_at) VALUES ('${result[0].id}', '${token}', '${tokenExpiredDt}')`, (error, result) => {
                            if (error == null) {
                                response.json({
                                    'status': 'success',
                                    'status-code': 200,
                                    'result': token
                                })
                            } else {
                                response.json({
                                    'status': 'failed',
                                    'status-code': 500,
                                    'result': 'Database error when login'
                                })
                            }
                        })

                    }
                } else {
                    response.json({
                        'status': 'failed',
                        'status-code': 404,
                        'result': 'User not found'
                    })
                }
            } else {
                response.json({
                    'status': 'failed',
                    'status-code': 500,
                    'result': 'Database error when getting user'
                })
            }
        })
    } else {
        response.json({
            'status': 'failed',
            'status-code': 422,
            'result': 'Please input username and password'
        })
    }
})

app.post('/api/register', (request, response) => {
    const { username, password, note } = request.body;
    if (username && password) {
        pool.query(`SELECT username FROM admin WHERE username = '${username}'`, (error, result) => {
            if (error) {
                response.json({
                    'status': 'failed',
                    'status-code': 500,
                    'result': 'Database error when getting user'
                })
            }
            
            if (result.length > 0) {
                response.json({
                    'status': 'failed',
                    'status-code': 403,
                    'result': 'Username already exist',
                })
            } else {
                const encryptedPassword = CryptoJS.AES.encrypt(password, process.env.SECRET_KEY).toString();
                pool.query(`INSERT INTO admin (username, password, note) VALUES ('${username}', '${encryptedPassword}', '${note}')`, (error, result) => {
                    if (error == null) {
                        response.json({
                            'status': 'success',
                            'status-code': 201,
                            'result': 'User registered'
                        })
                    } else {
                        response.json({
                            'status': 'failed',
                            'status-code': 500,
                            'result': 'Error when registering user'
                        })
                    }
                })
            }
        });
    } else {
        response.json({
            'status': 'failed',
            'status-code': 422,
            'result': 'Please input username and password'
        })
    }
})

app.listen(port, () => {
  console.log(`App listening on port ${port}`)
})