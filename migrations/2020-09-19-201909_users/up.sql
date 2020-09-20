-- Add uuis Extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Add tigger timestamp
CREATE OR REPLACE FUNCTION trigger_set_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE users (
  id uuid DEFAULT uuid_generate_v4(),
  PRIMARY KEY (id),
  lastname VARCHAR NOT NULL,
  firstname VARCHAR NOT NULL,
  email VARCHAR NOT NULL,
  password VARCHAR NOT NULL,
  created_at TIMESTAMPTZ DEFAULT (current_timestamp AT TIME ZONE 'UTC') NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT (current_timestamp AT TIME ZONE 'UTC') NOT NULL
);

CREATE TRIGGER set_timestamp_users
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp();
