CREATE TABLE IF NOT EXISTS token_provider (
   client_id varchar(100) NOT NULL PRIMARY KEY,
   provider varchar(100) NOT NULL
);

INSERT INTO token_provider values ('demo-client','SPRING');
INSERT INTO token_provider values ('admin-client','AUTH0');