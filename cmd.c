[root@localhost ~]# vi codeinjection.c
[root@localhost ~]# gcc codeinjection.c -o codeinject
[root@localhost ~]# ps -e | grep firefox
1433 ?        00:01:23 firefox
[root@localhost ~]# ./codeinject 1433
----Memory bytecode injector-----
Writing RIP 0x7ffd2f0abf40, process 1433
[root@localhost ~]#
