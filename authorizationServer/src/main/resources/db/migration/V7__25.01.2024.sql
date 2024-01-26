ALTER TABLE app_user ADD COLUMN otp varchar(64) DEFAULT NULL;
ALTER TABLE app_user ADD COLUMN otp_requested_at timestamp DEFAULT NULL;
