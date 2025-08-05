-- UUID拡張
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ユーザーテーブル
CREATE TABLE users (
    user_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(50) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash BYTEA NOT NULL,
    salt BYTEA NOT NULL,
    user_info_status INT,
    create_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- フレンドテーブル（typo修正＆制約追加）
CREATE TABLE friends (
    user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
    friend_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_blocked BOOLEAN DEFAULT FALSE,
    PRIMARY KEY (user_id, friend_id)  -- ← 同じ友達は1回まで
);

-- ユーザーのデバイス情報（IPなど）
CREATE TABLE user_device (
    device_uuid UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
    device_name VARCHAR(512),
    ip_address INET NOT NULL,
    port INTEGER NOT NULL,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_blocked BOOLEAN DEFAULT FALSE
);
