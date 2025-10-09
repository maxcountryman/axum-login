-- Create users table.
create table if not exists users
(
    id           integer primary key autoincrement,
    username     text not null unique,
    access_token text not null
);
