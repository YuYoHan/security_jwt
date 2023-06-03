create user 'cos'@'%' identified by 'cos1234';
grant all privileges on *.* to 'cos'@'%';
create database security;
use security;

select * from user;

