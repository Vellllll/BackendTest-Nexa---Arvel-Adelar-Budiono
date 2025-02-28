DELIMITER //
CREATE PROCEDURE sp_add_kary_arvel (
    IN nip VARCHAR(50),
    IN nama VARCHAR(200),
    IN alamat VARCHAR(200),
    IN gender ENUM('L','P'),
    IN photo TEXT,
    IN tgl_lahir DATE,
    IN status INT,
    IN insert_by VARCHAR(50),
    IN id INT
)
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN

        ROLLBACK;

        INSERT INTO log_trx_api (user_id, api, request, response, insert_at)
        VALUES (1, '/api/staff', CONCAT(
            '{"nip":', nip, ',"nama":', nama, ',"alamat":', alamat, ',"gender":', gender, ',"photo":', photo, ',"tgl_lahir":', tgl_lahir, ',"status":', status, ',"insert_by":', insert_by, ',"id":', id, '}'
        ), '{"status": "failed","status-code": 403,"result": "Nip already exist"}', CURRENT_TIMESTAMP);
    END;

    START TRANSACTION;
    INSERT INTO karyawan (nip, nama, alamat, gender, photo, tgl_lahir, status, insert_by, id) VALUES (nip, nama, alamat, gender, photo, tgl_lahir, status, insert_by, id);
    INSERT INTO log_trx_api (user_id, api, request, response, insert_at)
    VALUES (1, '/api/staff', CONCAT(
        '{"nip":', nip, ',"nama":', nama, ',"alamat":', alamat, ',"gender":', gender, ',"photo":', photo, ',"tgl_lahir":', tgl_lahir, ',"status":', status, ',"insert_by":', insert_by, ',"id":', id, '}'
    ), '{"status": "success","status-code": 201,"result": "Staff registered"}', CURRENT_TIMESTAMP);

    COMMIT;
END //
DELIMITER ;

CALL sp_add_kary_arvel(
    '20259081',
    'arvelbudi',
    'jl parang',
    'L',
    'jwehbrjhwb3jrbksdfkwnj3r92y3874238dhuwenwofjdnsf',
    '2004-04-04',
    1,
    'arvel',
    7
);

CREATE VIEW karyawan_arvel AS
SELECT 
    ROW_NUMBER() OVER (ORDER BY id) AS No,
    nip AS Nip,
    nama AS Nama,
    alamat AS Alamat,
    CASE 
        WHEN gender = 'L' THEN 'Laki - Laki'
        WHEN gender = 'P' THEN 'Perempuan'
        ELSE 'Tidak Diketahui'
    END AS Gend,
    DATE_FORMAT(tgl_lahir, '%d %M %Y') AS `Tanggal Lahir`
FROM karyawan;

SELECT * FROM karyawan_arvel;