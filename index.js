const express = require('express')
const app = express()
const port = 3000
const dotenv = require('dotenv');
const pool = require('./database');
const CryptoJS = require("crypto-js");
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const moment = require('moment');
const fs = require('fs');
const multer = require('multer');

const upload = multer({
    dest: './upload/',
});

dotenv.config();

app.use(bodyParser.json());

app.post('/api/login', (request, response) => {
    const { username, password } = request.body;
    if (username && password) {
        pool.query(`SELECT id, username, password FROM admin WHERE username = '${username}'`, (error, result) => {
            if (error == null) {
                if (result.length > 0) {
                    const decryptedPassword = CryptoJS.AES.decrypt(result[0].password.toString(), process.env.SECRET_KEY).toString(CryptoJS.enc.Utf8);
                    if (decryptedPassword == password) {
                        const currentDt = moment().format('YYYY-MM-DD HH:mm:ss');
                        const tokenExpiredDt = moment(currentDt).add(3600, 'seconds').format('YYYY-MM-DD HH:mm:ss');
                        const token = jwt.sign({
                            'username': username,
                            'password': password,
                            'expiredAt': tokenExpiredDt
                        }, process.env.SECRET_KEY, { expiresIn: '3600s' });

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

app.post('/api/staff', upload.single('photo'), (request, response) => {
    const header = request.headers['authorization'];
    let { nip, nama, alamat, gender, tgl_lahir, status, id } = request.body;
    const tokenValidation = verifyToken(header);

    if (tokenValidation.verified) {
        if (nip && nama) {
            if (isValidNip(nip)) {
                if (isValidNotSpecial(nama)) {
                    pool.query('SELECT nip FROM karyawan WHERE nip = ?', [nip], (error, result) => {
                        if (error == null) {
                            if (result.length > 0) {
                                response.status(403).json({
                                    'status': 'failed',
                                    'status-code': 403,
                                    'result': 'Nip already exist'
                                })
                            } else {
                                let base64Photo = null;
                                if (request.file) {
                                    base64Photo = new Buffer(fs.readFileSync(request.file.path)).toString("base64");
                                }

                                if (status == null) {
                                    status = 1;
                                }
    
                                pool.query('INSERT INTO karyawan (nip, nama, alamat, gender, photo, tgl_lahir, status, id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [nip, nama, alamat, gender, base64Photo, tgl_lahir, status, id] , (error, result) => {
                                    if (error == null) {
                                        response.json({
                                            'status': 'success',
                                            'status-code': 201,
                                            'result': 'Staff registered'
                                        })
                                    } else {
                                        response.json({
                                            'status': 'failed',
                                            'status-code': 500,
                                            'result': 'Error when registering staff'
                                        })
                                    }
                                })
                            }
                        } else {
                            response.status(500).json({
                                'status': 'failed',
                                'status-code': 500,
                                'result': 'Error when registering staff'
                            })
                        }
                    })
                } else {
                    response.status(403).json({
                        'status': 'failed',
                        'status-code': 403,
                        'result': 'Nama can not include special character'
                    })
                }
            } else {
                response.json({
                    'status': 'failed',
                    'status-code': 500,
                    'result': 'Nip is not valid'
                })
            }
        } else {
            response.json({
                'status': 'failed',
                'status-code': 422,
                'result': 'Field nip and nama are required'
            })
        }

    } else {
        response.json({
            'status': 'failed',
            'status-code': 401,
            'result': 'Unauthorized'
        })
    }
})

app.get('/api/staff', (request, response) => {
    const header = request.headers['authorization'];
    const { keyword, start, count } = request.query;
    const tokenValidation = verifyToken(header);

    if (tokenValidation.verified) {
        let whereQuery = '';
        if (keyword) {
            if (isValidNotSpecial(keyword)) {
                whereQuery = `WHERE nama LIKE '%${keyword}%' `;
            } else {
                return response.status(403).json({
                    'status': 'failed',
                    'status-code': 403,
                    'result': 'Nama can not include special character'
                })
            }
        }

        if (count) {
            whereQuery = whereQuery + `LIMIT ${count} `;
        }

        if (start) {
            whereQuery = whereQuery + `OFFSET ${start} `;
        }

        pool.query(`SELECT * FROM karyawan ${whereQuery} ORDER BY nip ASC`, (error, result) => {
            if (error == null) {
                response.status(200).json({
                    'status': 'success',
                    'status-code': 200,
                    'result': result
                })
            } else {
                response.status(500).json({
                    'status': 'failed',
                    'status-code': 500,
                    'result': 'Error when getting staff list'
                })
            }
        })
    } else {
        response.status(401).json({
            'status': 'failed',
            'status-code': 401,
            'result': 'Unauthorized'
        })
    }
})

app.put('/api/staff/:nip', (request, response) => {
    const header = request.headers['authorization'];
    const tokenValidation = verifyToken(header);
    const nip = request.params['nip'];

    if (tokenValidation.verified) {
        if (nip) {
            if (Object.keys(request.body).length > 0) {
                let tableColumns = [];
                pool.query('SHOW COLUMNS FROM karyawan', (error, result) => {
                    if (error == null) {
                        result.forEach(column => {
                            tableColumns.push(column['Field'])
                        })
    
                        let updateQuery = '';
                        let counter = 0;
                        for (let param in request.body) {
                            if (tableColumns.includes(param)) {
                                if (!isValidNotSpecial(request.body[param])) {
                                    console.log(param)
                                    return response.status(403).json({
                                        'status': 'failed',
                                        'status-code': 403,
                                        'result': `${param} can not include special character`
                                    })
                                }

                                if (counter == 0) {
                                    if (Number.isInteger(request.body[param])) {
                                        updateQuery = updateQuery + `SET ${param} = ${request.body[param]},`;
                                    } else {
                                        updateQuery = updateQuery + `SET ${param} = '${request.body[param]}',`;
                                    }
                                } else if (counter < Object.keys(request.body).length - 1) {
                                    if (Number.isInteger(request.body[param])) {
                                        updateQuery = updateQuery + ` ${param} = ${request.body[param]},`;
                                    } else {
                                        updateQuery = updateQuery + ` ${param} = '${request.body[param]}',`;
                                    }
                                } else {
                                    if (Number.isInteger(request.body[param])) {
                                        updateQuery = updateQuery + ` ${param} = ${request.body[param]}`;
                                    } else {
                                        updateQuery = updateQuery + ` ${param} = '${request.body[param]}'`;
                                    }
                                }
                            }
                            counter++;
                        }
            
                        pool.query(`UPDATE karyawan ${updateQuery} WHERE nip = ?`, [nip], (error, result) => {
                            if (error == null) {
                                return response.status(200).json({
                                    'status': 'success',
                                    'status-code': 200,
                                    'result': 'Staff updated'
                                })
                            } else {
                                return response.status(500).json({
                                    'status': 'failed',
                                    'status-code': 500,
                                    'result': 'Error when updating staff'
                                })
                            }
                        })
                    } else {
                        return response.status(500).json({
                            'status': 'failed',
                            'status-code': 500,
                            'result': 'Error when getting databse columns'
                        })
                    }
                })
            } else {
                return response.status(422).json({
                    'status': 'failed',
                    'status-code': 422,
                    'result': 'Please input the body fields'
                })
            }
        } else {
            return response.status(422).json({
                'status': 'failed',
                'status-code': 422,
                'result': 'nip parameter is required'
            })
        }
    } else {
        return response.status(401).json({
            'status': 'failed',
            'status-code': 401,
            'result': 'Unauthorized'
        })
    }
})

app.put('/api/staff/:nip/deactivate', (request, response) => {
    const header = request.headers['authorization'];
    const tokenValidation = verifyToken(header);
    const nip = request.params['nip'];

    if (tokenValidation.verified) {
        if (isValidNip(nip)) {
            pool.query('SELECT nip FROM karyawan WHERE nip = ?', [nip], (error, result) => {
                if (error == null) {
                    if (result.length == 0) {
                        return response.status(404).json({
                            'status': 'failed',
                            'status-code': 404,
                            'result': `Staff with nip ${nip} is not found`
                        })
                    }
                    pool.query('UPDATE karyawan SET status = 9 WHERE nip = ?', [nip], (error, result) => {
                        if (error == null) {
                            return response.status(200).json({
                                'status': 'success',
                                'status-code': 200,
                                'result': 'Staff deactivate'
                            })
                        } else {
                            return response.status(500).json({
                                'status': 'failed',
                                'status-code': 500,
                                'result': 'Error when deactivating staff'
                            })
                        }
                    })
                } else {
                    return response.status(500).json({
                        'status': 'failed',
                        'status-code': 500,
                        'result': 'Error when getting staff'
                    })
                }
            })
        } else {
            return response.status(403).json({
                'status': 'failed',
                'status-code': 403,
                'result': 'Nip is not valid'
            })
        }
    } else {
        return response.status(401).json({
            'status': 'failed',
            'status-code': 401,
            'result': 'Unauthorized'
        })
    }
})

const isValidNip = str => {
    const regex = /^\d{4}\d{4}$/;
    return regex.test(str);
}

const isValidNotSpecial = str => {
    const regex = /^[A-Za-z0-9 ]+$/;
    return regex.test(str);
}

const verifyToken = header => {
    const token = header && header.split(' ')[1];
    if (token) {
        try {
            const result = jwt.verify(token, process.env.SECRET_KEY)
            if (moment(result.expiredAt).unix() > moment().utc().unix()) {
                return {
                    verified: true,
                    username: result.username
                };
            } else {
                return {
                    verified: false,
                    username: null
                }
            }
        } catch (error) {
            return {
                verified: false,
                username: null
            }
        }
    } else {
        return {
            verified: false,
            username: null
        }
    }
}

app.listen(port, () => {
  console.log(`App listening on port ${port}`)
})