INSERT INTO role (id, name) VALUES (3, 'NORMAL_ADMIN');
INSERT INTO role (id, name) VALUES (4, 'SUPER_ADMIN');

INSERT INTO user_role (user_id, role_id) VALUES ('7f000001-8a56-11d1-818a-56e25ae50000', 3);
INSERT INTO user_role (user_id, role_id) VALUES ('7f000001-8a56-1695-818a-56687e880000', 4);

INSERT INTO authority (id, name) VALUES (3, 'ARTICLE_ADMIN');
INSERT INTO authority (id, name) VALUES (4, 'ARTICLE_SUPERADMIN');

INSERT INTO role_authority (role_id, authority_id) VALUES (3, 1);
INSERT INTO role_authority (role_id, authority_id) VALUES (3, 2);
INSERT INTO role_authority (role_id, authority_id) VALUES (3, 3);

INSERT INTO role_authority (role_id, authority_id) VALUES (4, 1);
INSERT INTO role_authority (role_id, authority_id) VALUES (4, 2);
INSERT INTO role_authority (role_id, authority_id) VALUES (4, 3);
INSERT INTO role_authority (role_id, authority_id) VALUES (4, 4);