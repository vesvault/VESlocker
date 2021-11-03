CREATE TABLE VESlocker (
    id binary(32) NOT NULL PRIMARY KEY,
    secret binary(32) NOT NULL,
    access_at DATETIME NOT NULL,
    access_count TINYINT UNSIGNED NOT NULL
);
