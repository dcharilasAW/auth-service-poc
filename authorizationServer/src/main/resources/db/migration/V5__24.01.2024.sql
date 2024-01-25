ALTER TABLE app_user ADD COLUMN client_id varchar(100) DEFAULT '2fbb93b1-8b4a-48ef-a75a-875078503a4d';

INSERT INTO app_user (id, client_id, username, password, active, created_at)
VALUES ('7f000001-8a56-11d1-818a-56e25ae50000', '9ac8b0c7-15c3-4d78-8ed5-02a8a5e1a253', 'admin', '{noop}secret', true, NOW());
INSERT INTO app_user (id, client_id, username, password, active, created_at)
VALUES ('7f000001-8a56-1695-818a-56687e880000', '9ac8b0c7-15c3-4d78-8ed5-02a8a5e1a253', 'superadmin', '{noop}secret', true, NOW());