CREATE DATABASE email_phone;
\connect email_phone;

CREATE USER repl_user WITH REPLICATION ENCRYPTED PASSWORD 'repl_user';
SELECT pg_create_physical_replication_slot('replication_slot');

CREATE TABLE emails (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL
);

CREATE TABLE phone_numbers (
    id SERIAL PRIMARY KEY,
    phone_number VARCHAR(20) NOT NULL
);

ALTER SYSTEM SET logging_collector = 'on';
ALTER SYSTEM SET log_directory = 'log';
ALTER SYSTEM SET log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log';
ALTER SYSTEM SET log_statement = 'all';
ALTER SYSTEM SET log_truncate_on_rotation = 'on';
ALTER SYSTEM SET log_rotation_age = '1d';
ALTER SYSTEM SET log_rotation_size = '10MB';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'log_reader') THEN
        CREATE ROLE log_reader;
    END IF;
END$$;

GRANT CONNECT ON DATABASE email_phone TO log_reader;
GRANT USAGE ON SCHEMA public TO log_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO log_reader;

-- Перемена прав доступа для каталога с логами
\! chmod -R a+r /var/lib/postgresql/data/log
