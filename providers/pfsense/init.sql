create database externalDNS;
show databases;
use externalDNS;
create table TxtRec(
    Dummy int primary key,
    Txt Text
);
select * from TxtRec;
