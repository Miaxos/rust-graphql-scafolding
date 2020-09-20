/*
 * Sessions are the way of representing user connection.
 * Sessions are unique
 * A use can have multiple sessions
 * When a user send a request, to be identified as a user authentificated
 * We check his csrf with his session and not just his jwt
 * His csrf should not be stored elsewhere than in the RUNTIME of the front-end
 * app.
**/
CREATE TABLE sessions (
  id SERIAL,
  PRIMARY KEY (id),
  key VARCHAR NOT NULL,
  csrf VARCHAR NOT NULL,
  userid uuid NOT NULL,
  FOREIGN KEY (userid) REFERENCES users (id),
  expiry TIMESTAMPTZ NOT NULL,
  invalidated boolean DEFAULT false NOT NULL,
  created_at TIMESTAMPTZ DEFAULT (current_timestamp AT TIME ZONE 'UTC') NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT (current_timestamp AT TIME ZONE 'UTC') NOT NULL
);
