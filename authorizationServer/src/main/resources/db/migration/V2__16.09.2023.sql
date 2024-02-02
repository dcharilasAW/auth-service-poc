INSERT INTO app_user (id, username, password, active, created_at, client_id, user_state)
    VALUES ('7f000001-8a56-11d1-818a-56e25ae30000', 'jim@hotmail.com', '{noop}secret', true, NOW(), '2fbb93b1-8b4a-48ef-a75a-875078503a4d', 'REGISTERED');
INSERT INTO app_user (id, username, password, active, created_at, client_id, user_state)
    VALUES ('7f000001-8a56-1695-818a-56687e770000', 'john@hotmail.com', '{noop}secret', true, NOW(), '2fbb93b1-8b4a-48ef-a75a-875078503a4d', 'REGISTERED');

INSERT INTO role (id, name) VALUES (1, 'UNVERIFIED_USER');
INSERT INTO role (id, name) VALUES (2, 'VERIFIED_USER');

INSERT INTO user_role (user_id, role_id) VALUES ('7f000001-8a56-11d1-818a-56e25ae30000', 1);
INSERT INTO user_role (user_id, role_id) VALUES ('7f000001-8a56-1695-818a-56687e770000', 2);

INSERT INTO authority (id, name) VALUES (1, 'GAME_VIEW');
INSERT INTO authority (id, name) VALUES (2, 'GAME_PLAY');

-- unverified users only can view games
INSERT INTO role_authority (role_id, authority_id) VALUES (2, 1);

-- verified users can also play games
INSERT INTO role_authority (role_id, authority_id) VALUES (1, 1);
INSERT INTO role_authority (role_id, authority_id) VALUES (1, 2);
