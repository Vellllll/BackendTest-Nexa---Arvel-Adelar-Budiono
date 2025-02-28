const express = require('express');
const app = express();
const dotenv = require('dotenv');
const pool = require('./database');
const CryptoJS = require("crypto-js");
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const moment = require('moment');
const fs = require('fs');
const multer = require('multer');
const winston = require('winston');
const { combine, timestamp, json, printf } = winston.format;
const timestampFormat = 'MMM-DD-YYYY HH:mm:ss';

const upload = multer({
    dest: './upload/',
});

const logger = winston.createLogger({
    format: combine(
        timestamp({ format: timestampFormat }),
        json(),
        printf(({ timestamp, level, message, ...data }) => {
            const response = {
                level,
                timestamp,
                message,
                data,
            };
            return JSON.stringify(response);
        })
    ),
    transports: [
        new winston.transports.Console()
    ],
});

dotenv.config();

app.use(bodyParser.json());

app.post('/api/login', (request, response) => {
    const log_header = 'post_api_login';
    logger.info(`${log_header}`, request.body);

    const { username, password } = request.body;
    if (username && password) {
        pool.query(`SELECT id, username, password FROM admin WHERE username = '${username}'`, (error, result) => {
            if (error == null) {
                if (result.length > 0) {
                    logger.info(`${log_header}: username and password are found`);

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
                                logger.info(`${log_header}: login successful`);
                                return response.status(200).json({
                                    'status': 'success',
                                    'status-code': 200,
                                    'result': token
                                })
                            } else {
                                logger.error(`${log_header}: login failed`, error);
                                return response.status(500).json({
                                    'status': 'failed',
                                    'status-code': 500,
                                    'result': 'Database error when login'
                                })
                            }
                        })
                    } else {
                        logger.info(`${log_header}: incorrect password`);
                        return response.status(401).json({
                            'status': 'failed',
                            'status-code': 401,
                            'result': 'Incorrect password'
                        })
                    }
                } else {
                    logger.info(`${log_header}: user is not found`)
                    return response.status(404).json({
                        'status': 'failed',
                        'status-code': 404,
                        'result': 'User is not found'
                    })
                }
            } else {
                logger.error(`${log_header}: error when querying username and password in database`, error);
                return response.status(500).json({
                    'status': 'failed',
                    'status-code': 500,
                    'result': 'Database error when getting user'
                })
            }
        })
    } else {
        logger.info(`${log_header}: username and password are not found`);
        return response.status(422).json({
            'status': 'failed',
            'status-code': 422,
            'result': 'Please input username and password'
        })
    }
})

app.post('/api/register', (request, response) => {
    const log_header = 'post_api_register';
    logger.info(`${log_header}`, request.body);

    const { username, password, note } = request.body;
    if (username && password) {
        pool.query(`SELECT username FROM admin WHERE username = '${username}'`, (error, result) => {
            if (error) {
                logger.info(`${log_header}: error when getting existing user`)
                return response.status(500).json({
                    'status': 'failed',
                    'status-code': 500,
                    'result': 'Database error when getting user'
                })
            }
            
            if (result.length > 0) {
                logger.info(`${log_header}: username already exist`);
                return response.status(403).json({
                    'status': 'failed',
                    'status-code': 403,
                    'result': 'Username already exist',
                })
            } else {
                logger.info(`${log_header}: registering user`);
                const encryptedPassword = CryptoJS.AES.encrypt(password, process.env.SECRET_KEY).toString();
                pool.query(`INSERT INTO admin (username, password, note) VALUES ('${username}', '${encryptedPassword}', '${note}')`, (error, result) => {
                    if (error == null) {
                        logger.info(`${log_header}: registration successful`)
                        return response.status(201).json({
                            'status': 'success',
                            'status-code': 201,
                            'result': 'User registered'
                        })
                    } else {
                        logger.error(`${log_header}: error when registering user`, error)
                        return response.status(500).json({
                            'status': 'failed',
                            'status-code': 500,
                            'result': 'Error when registering user'
                        })
                    }
                })
            }
        });
    } else {
        logger.info(`${log_header}: username and password are not found`);
        return response.status(422).json({
            'status': 'failed',
            'status-code': 422,
            'result': 'Please input username and password'
        })
    }
})

app.post('/api/staff', upload.single('photo'), (request, response) => {
    const log_header = 'post_api_staff';
    logger.info(`${log_header}`, request.body);

    const header = request.headers['authorization'];
    let { nip, nama, alamat, gend, tgl_lahir, status, id } = request.body;
    const tokenValidation = verifyToken(header);

    if (tokenValidation.verified) {
        logger.info(`${log_header}: token valid`);
        if (nip && nama) {
            if (isValidNip(nip)) {
                logger.info(`${log_header}: nip valid`);
                if (isValidNotSpecial(nama)) {
                    logger.info(`${log_header}: nama valid`)
                    pool.query('SELECT nip FROM karyawan WHERE nip = ?', [nip], (error, result) => {
                        if (error == null) {
                            if (result.length > 0) {
                                logger.info(`${log_header}: nip already exist`);
                                return response.status(403).json({
                                    'status': 'failed',
                                    'status-code': 403,
                                    'result': 'Nip already exist'
                                })
                            } else {
                                logger.info(`${log_header}: registering staff`)
                                let base64Photo = null;
                                if (request.file) {
                                    logger.info(`${log_header}: converting photo to base64`);
                                    base64Photo = `data:${request.file.mimetype};base64,${new Buffer(fs.readFileSync(request.file.path)).toString("base64")}`;
                                }

                                if (status == null) {
                                    logger.info(`${log_header}: set staff status to 1`);
                                    status = 1;
                                }
    
                                pool.query('INSERT INTO karyawan (nip, nama, alamat, gend, photo, tgl_lahir, status, id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [nip, nama, alamat, gend, base64Photo, tgl_lahir, status, id] , (error, result) => {
                                    if (error == null) {
                                        logger.info(`${log_header}: staff registered`);
                                        return response.status(201).json({
                                            'status': 'success',
                                            'status-code': 201,
                                            'result': 'Staff registered'
                                        });
                                    } else {
                                        logger.error(`${log_header}: error when registering staff`, error);
                                        return response.status(500).json({
                                            'status': 'failed',
                                            'status-code': 500,
                                            'result': 'Error when registering staff'
                                        });
                                    }
                                })
                            }
                        } else {
                            logger.error(`${log_header}: error when registering staff`, error);
                            return response.status(500).json({
                                'status': 'failed',
                                'status-code': 500,
                                'result': 'Error when registering staff'
                            })
                        }
                    })
                } else {
                    logger.info(`${log_header}: nama can not include special character`);
                    return response.status(403).json({
                        'status': 'failed',
                        'status-code': 403,
                        'result': 'Nama can not include special character'
                    })
                }
            } else {
                logger.info(`${log_header}: nip invalid`)
                return response.status(500).json({
                    'status': 'failed',
                    'status-code': 500,
                    'result': 'Nip is not valid'
                })
            }
        } else {
            logger.info(`${log_header}: nip and nama are not found`)
            return response.status(422).json({
                'status': 'failed',
                'status-code': 422,
                'result': 'Field nip and nama are required'
            })
        }

    } else {
        logger.info(`${log_header}: token invalid`);
        return response.status(401).json({
            'status': 'failed',
            'status-code': 401,
            'result': 'Unauthorized'
        })
    }
})

app.get('/api/staff', (request, response) => {
    const log_header = 'get_api_staff';
    logger.info(`${log_header}`, request.query);

    const header = request.headers['authorization'];
    const { keyword, start, count } = request.query;
    const tokenValidation = verifyToken(header);

    if (tokenValidation.verified) {
        logger.info(`${log_header}: token valid`)

        let whereQuery = '';
        if (keyword) {
            logger.info(`${log_header}: filtering nama by keyword`)
            if (isValidNotSpecial(keyword)) {
                whereQuery = ` WHERE nama LIKE '%${keyword}%' `;
            } else {
                logger.info(`${log_header}: keyword can not include specila character`);
                return response.status(403).json({
                    'status': 'failed',
                    'status-code': 403,
                    'result': 'Keyword can not include special character'
                })
            }
        }

        let limitQuery = '';
        if (count) {
            logger.info(`${log_header}: set the data count`);
            limitQuery = limitQuery + `LIMIT ${count} `;
        }

        if (start) {
            logger.info(`${log_header}: set the offset data`);
            limitQuery = limitQuery + `OFFSET ${start} `;
        }

        pool.query(`SELECT * FROM karyawan ${whereQuery} ORDER BY nip ASC ${limitQuery}`, (error, result) => {
            if (error == null) {
                logger.info(`${log_header}: returning staff list`);
                return response.status(200).json({
                    'status': 'success',
                    'status-code': 200,
                    'result': result
                })
            } else {
                logger.error(`${log_header}: error when getting staff list`, error);
                return response.status(500).json({
                    'status': 'failed',
                    'status-code': 500,
                    'result': 'Error when getting staff list'
                })
            }
        })
    } else {
        logger.info(`${log_header}: token invalid`);
        return response.status(401).json({
            'status': 'failed',
            'status-code': 401,
            'result': 'Unauthorized'
        })
    }
})

app.put('/api/staff/:nip', (request, response) => {
    const log_header = 'put_api_staff';
    logger.info(`${log_header}`, request.body);

    const header = request.headers['authorization'];
    const tokenValidation = verifyToken(header);
    const nip = request.params['nip'];

    if (tokenValidation.verified) {
        logger.info(`${log_header}: token valid`);
        if (nip) {
            if (Object.keys(request.body).length > 0) {
                logger.info(`${log_header}: body field is exist`);

                let tableColumns = [];
                pool.query('SHOW COLUMNS FROM karyawan', (error, result) => {
                    if (error == null) {
                        logger.info(`${log_header}: editing staff data`);
                        result.forEach(column => {
                            tableColumns.push(column['Field'])
                        })
    
                        let updateQuery = '';
                        let counter = 0;
                        for (let param in request.body) {
                            if (tableColumns.includes(param)) {
                                if (!isValidNotSpecial(request.body[param])) {
                                    logger.info(`${log_header}: ${param} can not include special character`);
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
                            } else {
                                return response.status(403).json({
                                    'status': 'failed',
                                    'status-code': 403,
                                    'result': `${param} field is not in database column`
                                })
                            }
                            counter++;
                        }
            
                        pool.query(`UPDATE karyawan ${updateQuery} WHERE nip = ?`, [nip], (error, result) => {
                            if (error == null) {
                                logger.info(`${log_header}: staff updated`);
                                return response.status(200).json({
                                    'status': 'success',
                                    'status-code': 200,
                                    'result': 'Staff updated'
                                })
                            } else {
                                logger.error(`${log_header}: error when updating staff`, error);
                                return response.status(500).json({
                                    'status': 'failed',
                                    'status-code': 500,
                                    'result': 'Error when updating staff'
                                })
                            }
                        })
                    } else {
                        logger.error(`${log_header}: error when getting database column`, error);
                        return response.status(500).json({
                            'status': 'failed',
                            'status-code': 500,
                            'result': 'Error when getting database columns'
                        })
                    }
                })
            } else {
                logger.info(`${log_header}: body field is empty`);
                return response.status(422).json({
                    'status': 'failed',
                    'status-code': 422,
                    'result': 'Please input the body fields'
                })
            }
        } else {
            logger.info(`${log_header}: nip parameter is required`);
            return response.status(422).json({
                'status': 'failed',
                'status-code': 422,
                'result': 'nip parameter is required'
            })
        }
    } else {
        logger.info(`${log_header}: token invalid`);
        return response.status(401).json({
            'status': 'failed',
            'status-code': 401,
            'result': 'Unauthorized'
        })
    }
})

app.put('/api/staff/:nip/deactivate', (request, response) => {
    const log_header = 'put_api_staff_deactivate';
    logger.info(`${log_header}`);

    const header = request.headers['authorization'];
    const tokenValidation = verifyToken(header);
    const nip = request.params['nip'];

    if (tokenValidation.verified) {
        logger.info(`${log_header}: token valid`);
        if (isValidNip(nip)) {
            logger.info(`${log_header}: nip valid`);
            pool.query('SELECT nip FROM karyawan WHERE nip = ?', [nip], (error, result) => {
                if (error == null) {
                    if (result.length == 0) {
                        logger.info(`${log_header}: staff with nip ${nip} is not found`);
                        return response.status(404).json({
                            'status': 'failed',
                            'status-code': 404,
                            'result': `Staff with nip ${nip} is not found`
                        })
                    }
                    pool.query('UPDATE karyawan SET status = 9 WHERE nip = ?', [nip], (error, result) => {
                        if (error == null) {
                            logger.info(`${log_header}: staff deactivate`);
                            return response.status(200).json({
                                'status': 'success',
                                'status-code': 200,
                                'result': 'Staff deactivate'
                            })
                        } else {
                            logger.error(`${log_header}: error when deactivating staff`, error);
                            return response.status(500).json({
                                'status': 'failed',
                                'status-code': 500,
                                'result': 'Error when deactivating staff'
                            })
                        }
                    })
                } else {
                    logger.error(`${log_header}: error when getting staff`, error);
                    return response.status(500).json({
                        'status': 'failed',
                        'status-code': 500,
                        'result': 'Error when getting staff'
                    })
                }
            })
        } else {
            logger.info(`${log_header}: nip invalid`);
            return response.status(403).json({
                'status': 'failed',
                'status-code': 403,
                'result': 'Nip is not valid'
            })
        }
    } else {
        logger.info(`${log_header}: unauthorized`);
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

app.listen(process.env.APP_PORT, () => {
  console.log(`Listening on port ${process.env.APP_PORT}`)
})