-- Add migration script here
CREATE TABLE accounts (
    id BIGINT GENERATED ALWAYS AS IDENTITY,
    username varchar(255) NOT NULL UNIQUE,
    password_hash varchar(255) NOT NULL,
    PRIMARY KEY(id)
);

CREATE TABLE sessions (
    id BIGINT GENERATED ALWAYS AS IDENTITY,
    accounts_id BIGINT NOT NULL REFERENCES accounts(id),
    session_id char(27) NOT NULL,
    PRIMARY KEY(id),
    UNIQUE(accounts_id),
    UNIQUE(session_id)
);
