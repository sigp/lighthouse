create table if not exists store (
    col text not null,
    key bytea not null,
    value bytea not null,
    primary key (col, key)
);

INSERT INTO store (col, key, value)
VALUES ('example', decode('aabbcc', 'hex'), decode('112233', 'hex'));