CREATE TABLE pat_authorizations (
    id varchar(100) NOT NULL,
    name varchar(100) NOT NULL,
    description varchar(100),
    token varchar(1000) NOT NULL,
    principal varchar(100) NOT NULL,
    scopes varchar(1000) NOT NULL,
    issued_at timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
    expires_at timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
    not_before timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
    PRIMARY KEY (id)
);
