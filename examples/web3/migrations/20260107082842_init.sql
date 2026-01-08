-- Add migration script here
create table if not exists users(
    id           integer primary key autoincrement,
    username     text not null unique,
    address      text not null unique
);