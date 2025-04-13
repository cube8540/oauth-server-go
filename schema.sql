create sequence account_id_seq;
create table account (
    id bigint primary key default nextval('account_id_seq'),
    username varchar(128) not null unique ,
    password varchar(128) not null,
    active bool not null default false,
    active_token varchar(128),
    active_token_expires timestamp,
    password_token varchar(128),
    password_token_expires timestamp,
    last_mod_password_at timestamp,
    reg_at timestamp default now(),
    mod_at timestamp
);
alter sequence account_id_seq owned by account.id;

create sequence oauth2_scope_id_seq;
create table oauth2_scope (
    id bigint primary key default nextval('oauth2_scope_id_seq'),
    code varchar(128) not null ,
    scope_name varchar(128) not null ,
    description text,
    reg_at timestamp default now()
);
alter sequence oauth2_scope_id_seq owned by oauth2_scope.id;

create sequence oauth2_client_id_seq;
create table oauth2_client (
    id bigint primary key default nextval('oauth2_client_id_seq'),
    client_id varchar(128) not null unique ,
    client_name varchar(128),
    client_type varchar(32) not null,
    secret varchar(128) not null ,
    owner_id varchar(128) not null ,
    redirect_uris text,
    reg_at timestamp default now()
);
alter sequence oauth2_client_id_seq owned by oauth2_client.id;

create table oauth2_client_scope (
    client_id bigint,
    scope_id bigint,

    primary key (client_id, scope_id)
);

create sequence oauth2_authorization_code_seq;
create table oauth2_authorization_code (
    id bigint primary key default nextval('oauth2_authorization_code_seq'),
    code varchar(128) not null unique ,
    client_id bigint not null,
    username varchar(128) not null,
    redirect varchar(128) not null,
    code_challenge varchar(128),
    code_challenge_method varchar(32),
    state text,
    issued_at timestamp default now(),
    expired_at timestamp not null
);
alter sequence oauth2_authorization_code_seq owned by oauth2_authorization_code.id;

create table oauth2_code_scope(
    code_id bigint,
    scope_id bigint,

    primary key (code_id, scope_id)
);

create sequence oauth2_access_token_id_seq;
create table oauth2_access_token (
    id bigint primary key default nextval('oauth2_access_token_id_seq'),
    token varchar(128) not null unique,
    client_id bigint not null ,
    username varchar(128),
    issued_at timestamp default now(),
    expired_at timestamp not null
);
alter sequence oauth2_access_token_id_seq owned by oauth2_access_token.id;

create table oauth2_token_scope(
    token_id bigint,
    scope_id bigint,

    primary key (token_id, scope_id)
);

create sequence oauth2_refresh_token_id_seq;
create table oauth2_refresh_token (
    id bigint primary key default nextval('oauth2_refresh_token_id_seq'),
    token varchar(128) not null unique ,
    access_token_id bigint not null ,
    issued_at timestamp default now(),
    expired_at timestamp not null
);
alter sequence oauth2_refresh_token_id_seq owned by oauth2_refresh_token.id;