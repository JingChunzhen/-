
/****************************************************************************************************************************************/
--1-- ���м��ģ�����һ�������˻������ݿ⣬�����˻����д洢���û��ĵ�¼��������ȸ�����Ϣ
--2-- �½���һ�����ݿ�Account��������һ��Personal_Account��ʹ���ⲿ�������������弯�ϣ���ӳ�䵽���ݿ��еĺ����зֱ���encrypt_U��decrypt_U 
--3-- ʹ���������ĺ��������ݿ���Personal_Account���е�ĳЩ�н��м��ܻ��߽��ܲ�������Կ�����ڷǱ�̨PC�����ⲿӲ����
--4-- ���ݿ⺯����ȡ�ⲿ�ļ���ҪȨ��
--5-- ���ݿ����Ա��Ȼ������Personal_Account���в������ݣ����Ǽ������ݿ����Ա���������ĵ���ʽ����в�������
--6-- ����������ݾ��� trigger_insert_Persoanl_Account ���������� trigger_update_Personal_Account���������Զ�������ĳЩ��
--7-- judge����һ����Ǳ�����ʾ���������ģ�����������
--8-- �ⲿ�ļӽ��ܺ�������AES�㷨���������ΪC#
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
--�����Ƕ���������Ĳ��ԣ����Լ��ܽ��ܺ����Ĺ��ܣ������Դ������Ĺ���
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
       --���Խ��--
--1-- insert�������ɹ�
--2-- update�������ɹ�
/**************************/

/***************************************************************************************************************************************/
--1-- �����е�Account���ݿ��ϴ���һ����Personal_InfoͬʱҲ����һ����ͼPersonal_Info_View��Ҫ�󵱼��ܻ������ͼ��ʱ�򣬱������仯
--2-- �û��ڲ鿴�Ͳ���Account���ݿ��Presonal_Info��ֻ��������������ͼ�Ͻ���
--3-- ����Ա������Personal_Account���в���͸������ݣ�������������ͼ�У���Ȼ���ܵ�����Ȼ�����ĵ���ʽ���֣�δ���ܵ���Ȼ�������ĵ���ʽ����
--4-- ���Ǽ������Աÿ������в�������ݶ��������ĵ���ʽ���ֵ�
--5-- Personal_Info_Viewÿ�ζ���Ҫȥ�������ڼ����м����Ҳһ��
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
--���������������ȷ��
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
       --���Խ��--
--1-- insert�������ɹ�
--2-- update�������ɹ�
/**************************/

/*****************************************************************************************/
                                 --Q & A--
--1-- �����м���Ǹ�����Աʹ�õģ�����Ա���Ծ�����һ�м��ܣ����߽�����һ��
--2-- �����������뷨�������м����ʹ��ʱ������ͼ���ޱ�Ҫ
--3-- ������û���Ҫ�鿴������Ϣ��һЩ��Ϣ��Ҫ�����ĵ���ʽ���֣����������Ҫ��ͼ
--4-- ��һ��д���У����ܲ����ᴥ��trigger_update_Personal_Account�����Ǽ��ܽ��ܲ����Իᴥ��
/*****************************************************************************************/