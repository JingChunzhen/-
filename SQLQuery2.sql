
/****************************************************************************************************************************************/
--1-- 本中间件模拟的是一个银行账户的数据库，个人账户表中存储了用户的登录名和密码等个人信息
--2-- 新建了一个数据库Account，其中有一个Personal_Account表，使用外部函数创建程序定义集合，并映射到数据库中的函数中分别是encrypt_U和decrypt_U 
--3-- 使用所创建的函数对数据库中Personal_Account表中的某些列进行加密或者解密操作，秘钥存在于非本台PC机的外部硬件中
--4-- 数据库函数读取外部文件需要权限
--5-- 数据库管理员仍然可以向Personal_Account表中插入数据，我们假设数据库管理员都是以明文的形式向表中插入数据
--6-- 所插入的数据经过 trigger_insert_Persoanl_Account 触发器联合 trigger_update_Personal_Account触发器，自动加密了某些列
--7-- judge表是一个标记表，以显示哪列是密文，哪列是明文
--8-- 外部的加解密函数基于AES算法，编程语言为C#
/****************************************************************************************************************************************/

create database Account
on primary
(
name=Student_dat,
filename='d:\DB\Account_dat.mdf',
size=50,
filegrowth=5%
)
log on 
(
name=Student_log,
filename='d:\DB\Account_log.ldf',
size=2,
maxsize=5,
filegrowth=1
)

use Account
create table Personal_Account
(
UserID nvarchar(128) primary key,
Accountnum nvarchar(128),
Passwd nvarchar(128),
Name nvarchar(128),
Tel nvarchar(128)
)

use Account
create table judge   
(
UserID int primary key,
Accountnum int,
Passwd int,
Name int,
Tel int
)

exec sp_configure 'show advanced options','1'
go
reconfigure ;
go
exec sp_configure 'clr enabled','1'
go
reconfigure
exec sp_configure 'show advanced options','1';
go

Alter Database Account SET TRUSTWORTHY ON  

drop assembly SQL_CLR_TEST_2
use Account
create assembly SQL_CLR_TEST_2
authorization dbo
from 'D:\Csharp\SQL_CLR_TEST_2\SQL_CLR_TEST_2\bin\Debug\SQL_CLR_TEST_2.dll'
with permission_set = unsafe ;        
go

create function decrypt_U(@cipherText nvarchar(128))
returns nvarchar(128)
as external name 
SQL_CLR_TEST_2.UserDefinedFunctions.test_decrypt_AES_U ;
go

create function encrypt_U(@plainText nvarchar(128))
returns nvarchar(128)
as external name 
SQL_CLR_TEST_2.UserDefinedFunctions.test_encrypt_AES_U ;
go

if(exists(select * from sysobjects where name='trigger_update_Personal_Account'))
drop trigger trigger_update_Personal_Account
use Account
go
create trigger trigger_update_Personal_Account
on Personal_Account
after update 
as 
declare @temp int ;
begin 
if update(Passwd)
begin 
 select @temp = Passwd from judge 
 if @temp='1' begin update judge set dbo.judge.Passwd=0;end
 else begin update judge set dbo.judge.Passwd=1;end 
end 
if update(UserID)
begin 
 select @temp = UserID from judge 
 if @temp='1' begin update judge set UserID=0;end 
 else begin update judge set UserID=1;end 
end 
if update(Accountnum)
begin 
 select @temp = Accountnum from judge 
 if @temp='1' begin update judge set judge.Accountnum=0;end
 else begin update judge set judge.Accountnum=1;end
end 

if update(Name)
begin 
 select @temp = Name from judge
 if @temp='1' begin update judge set dbo.judge.Name=0;end
 else begin update judge set dbo.judge.Name=1;end 
end 
if update(Tel)
begin 
 select @temp = Tel from judge
 if @temp='1' begin update judge set Tel=0;end
 else begin update judge set Tel=1;end 
end 
end 

if(exists(select * from sysobjects where name='trigger_insert_Personal_Account'))
drop trigger trigger_insert_Personal_Account
go
create trigger trigger_insert_Personal_Account  
on Personal_Account
after insert 
as 
begin
declare @temp_UserID nvarchar(128)
select @temp_UserID=UserID from inserted
if (select Accountnum from judge)=1
begin
 update Personal_Account 
 set Accountnum = dbo.encrypt_U (Accountnum) 
 where UserID=@temp_UserID
 update judge
 set Accountnum=1;
end 
if (select Passwd from judge)=1
begin 
 update Personal_Account
 set Passwd =dbo.encrypt_U(Passwd)
 where UserID=@temp_UserID
 update judge
 set Passwd=1;
end 
if (select Name from judge)=1
begin 
 update Personal_Account
 set Name =dbo.encrypt_U(Name)
 where UserID=@temp_UserID
 update judge
 set Name=1;
end 
if (select Tel from judge)=1
begin 
 update Personal_Account
 set Tel =dbo.encrypt_U(Tel)
 where UserID=@temp_UserID
 update judge
 set Tel=1;
end 
end 
go 

/********************************************************************/
--以下是对上述代码的测试，测试加密解密函数的功能，并测试触发器的功能
/********************************************************************/
use Account
select *
from dbo.judge

update Personal_Account
set Passwd = dbo.encrypt_U(Passwd)

update Personal_Account
set Passwd= dbo.decrypt_U(Passwd)

update Personal_Account  
set Tel= dbo.decrypt_U(Tel)

use Account
select *
from Personal_Account

update judge
set Passwd = 0

delete 
from Personal_Account
where UserID ='004'


insert
into Personal_Account(UserID,Accountnum,Passwd,Name,Tel)
values('003','201240704003','126871','jingchun','1578116')
go

insert   
into Personal_Account(UserID,Accountnum,Passwd,Name,Tel)
values('004','20124006','4006','JCZ','1578119');
go

delete
from Personal_Account
where UserID = 003

/**************************/
       --测试结果--
--1-- insert触发器成功
--2-- update触发器成功
/**************************/

/***************************************************************************************************************************************/
--1-- 在已有的Account数据库上创建一个表Personal_Info同时也创建一个视图Personal_Info_View，要求当加密或解密视图的时候，表不发生变化
--2-- 用户在查看和操作Account数据库的Presonal_Info，只能在所创建的视图上进行
--3-- 管理员可以向Personal_Account表中插入和更新数据，并会体现在视图中，当然加密的列仍然以密文的形式体现，未加密的仍然是以明文的形式体现
--4-- 我们假设管理员每次向表中插入的数据都是以明文的形式体现的
--5-- Personal_Info_View每次都需要去创建，在加密中间件中也一样
/***************************************************************************************************************************************/
use Account
create table Personal_Info
(
UserID  nvarchar(128) primary key ,
Name nvarchar(128),
ID nvarchar(128),
Tel nvarchar(128),
)

use Account
IF EXISTS (SELECT TABLE_NAME FROM INFORMATION_SCHEMA.VIEWS WHERE TABLE_NAME = N'Personal_Info_View')
DROP View Personal_Info_View
use Account 
go
create view Personal_Info_View
as
select UserID , Name , dbo.encrypt_U(ID) as ID , dbo.encrypt_U(Tel) as Tel
from Personal_Info 

use Account 
go 
if(exists(select * from sysobjects where name='trigger_update_Personal_Info_View'))
drop trigger trigger_update_Personal_Info_View
create trigger trigger_update_Personal_Info_view  
on Personal_Info_View
instead of update
as
begin
 if update(Name)
 update Personal_Info_View 
 set Name = (select Name from inserted where UserID = inserted.UserID) 

 if update(ID)
 update Personal_Info_View
 set ID= (select dbo.encrypt_U(ID) from inserted where UserID = inserted.UserID)  

 if update(Tel)
 update Personal_Info_View
 set Tel = (select dbo.encrypt_U(Tel) from inserted where UserID = inserted.UserID) 

end


use Account 
go 
if(exists(select * from sysobjects where name='trigger_insert_Personal_Info_View'))
drop trigger trigger_insert_Personal_Info_View
create trigger trigger_insert_Personal_Info_View
on Personal_Info_View 
instead of insert 
as
begin 
 insert into  Personal_Info_View(UserID,Name, ID ,Tel)
 select  UserID,Name, dbo.encrypt_U(ID) ,dbo.encrypt_U(Tel)
 from inserted 
end 

/***********************/
--测试上述代码的正确性
/***********************/
use Account 
select * 
from Personal_Info

select *
from Personal_Info_View

delete 
from Personal_Info_View
where UserID = 00003

select * 
from judge_Personal_Info

insert into Personal_Info
values('00003','MaggieQ','370202','1578119');

update Personal_Info
set ID = '142301'
where UserID = '00001';  

/**************************/
       --测试结果--
--1-- insert触发器成功
--2-- update触发器成功
/**************************/

/*****************************************************************************************/
                                 --Q & A--
--1-- 加密中间件是给管理员使用的，管理员可以决定哪一行加密，或者解密哪一行
--2-- 基于上述的想法，加密中间件在使用时创建视图似无必要
--3-- 如果是用户需要查看表中信息，一些信息需要以密文的形式体现，这种情况需要视图
--4-- 第一个写法中，加密操作会触发trigger_update_Personal_Account，但非加密解密操作仍会触发
/*****************************************************************************************/