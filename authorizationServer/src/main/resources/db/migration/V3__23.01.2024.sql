CREATE TABLE oauth2_registered_client
(
    id                            varchar(100)                            NOT NULL,
    client_id                     varchar(100)                            NOT NULL,
    client_id_issued_at           timestamp     DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret                 varchar(200)  DEFAULT NULL,
    client_secret_expires_at      timestamp     DEFAULT NULL,
    client_name                   varchar(200)                            NOT NULL,
    client_authentication_methods varchar(1000)                           NOT NULL,
    authorization_grant_types     varchar(1000)                           NOT NULL,
    redirect_uris                 varchar(1000) DEFAULT NULL,
    scopes                        varchar(1000)                           NOT NULL,
    client_settings               varchar(2000)                           NOT NULL,
    token_settings                varchar(2000)                           NOT NULL,
    post_logout_redirect_uris     varchar                                 NULL,
    PRIMARY KEY (id)
);

CREATE TABLE oauth_access_token (
                                    authentication_id varchar(255) NOT NULL PRIMARY KEY,
                                    token_id varchar(255) NOT NULL,
                                    token bytea NOT NULL,
                                    user_name varchar(255) NOT NULL,
                                    client_id varchar(255) NOT NULL,
                                    authentication bytea NOT NULL,
                                    refresh_token varchar(255) NOT NULL
);

CREATE TABLE oauth_refresh_token (
                                     token_id varchar(255) NOT NULL,
                                     token bytea NOT NULL,
                                     authentication bytea NOT NULL
);