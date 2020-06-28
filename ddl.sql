create table if not exists users (
    id serial primary key,
    first_name varchar(255) not null default '',
    last_name varchar(255) not null default '',
    username varchar(255) not null unique,
    email varchar(255) not null unique,
    password varchar(255) not null,
    admin boolean not null default false,
    created_at timestamp with time zone not null default current_timestamp
);

create table if not exists runs (
    id serial primary key,
    user_id integer references users(id) on delete set null,
    run_date timestamp with time zone not null default current_timestamp,
    distance float not null default 0,
    duration float not null default 0,
    title varchar(255) not null default 'Normal Run',
    description text not null default '',
    units varchar(2) not null default 'mi',
    location varchar(255) not null default '',
    created_at timestamp with time zone not null default current_timestamp
);