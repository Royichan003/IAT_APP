CREATE TABLE IF NOT EXISTS server_info (
    id SERIAL PRIMARY KEY,
    device_id TEXT,
    user_id TEXT,
    host TEXT,
    port TEXT,
    username TEXT,
    password TEXT,
    login_string TEXT
);

