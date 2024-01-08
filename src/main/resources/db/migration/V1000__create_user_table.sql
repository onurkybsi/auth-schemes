CREATE TABLE IF NOT EXISTS person (
  id SERIAL PRIMARY KEY,
  first_name VARCHAR(50) NOT NULL,
  last_name VARCHAR(50) NOT NULL,
  email VARCHAR(50) UNIQUE NOT NULL,
  hashed_password VARCHAR NOT NULL,
  modification_date TIMESTAMP NOT NULL,
  creation_date TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS user_authority (
  user_id INTEGER NOT NULL REFERENCES person(id) ON DELETE CASCADE,
  name VARCHAR(50) NOT NULL,
  creation_date TIMESTAMP NOT NULL,
  PRIMARY KEY (user_id, name)
);
CREATE TABLE IF NOT EXISTS client (
  id SERIAL PRIMARY KEY,
  name VARCHAR UNIQUE NOT NULL,
  api_key VARCHAR UNIQUE NOT NULL,
  hashed_client_secret VARCHAR NOT NULL,
  modification_date TIMESTAMP NOT NULL,
  creation_date TIMESTAMP NOT NULL
);
CREATE TABLE IF NOT EXISTS client_authority (
  client_id INTEGER NOT NULL REFERENCES client(id) ON DELETE CASCADE,
  name VARCHAR(50) NOT NULL,
  creation_date TIMESTAMP NOT NULL,
  PRIMARY KEY (client_id, name)
);