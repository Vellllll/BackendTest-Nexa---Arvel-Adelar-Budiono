CREATE TABLE admin (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(100),
    password VARBINARY(100),
    note VARCHAR(100)
);

CREATE TABLE admin_token (
    id INT PRIMARY KEY AUTO_INCREMENT,
    id_admin INT,
    token TEXT,
    expired_at TIMESTAMP
);

CREATE TABLE karyawan (
    nip VARCHAR(50) PRIMARY KEY,
    nama VARCHAR(200) NOT NULL,
    alamat VARCHAR(200),
    gender ENUM('L','P'),
    photo TEXT,
    tgl_lahir DATE,
    status INT DEFAULT 1,
    insert_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    insert_by VARCHAR(50),
    update_at TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    update_by VARCHAR(50),
    id INT NOT NULL
);