CREATE TABLE IF NOT EXISTS user_state_role (
   user_state varchar(100) NOT NULL PRIMARY KEY,
   role_id integer NOT NULL
);

INSERT INTO user_state_role values ('REGISTERED',1);
INSERT INTO user_state_role values ('VERIFIED',2);