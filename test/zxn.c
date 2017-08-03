#include <stdlib.h>
#include <stdio.h>
#include <mysql/mysql.h>
int main(int argc,char *argv[]){
	MYSQL my_connection;
	int i;
	mysql_init(&my_connection);
	mysql_real_connect(&my_connection,"127.0.0.1","root","root","foo",0,NULL,0);
	int res4 = mysql_query(&my_connection, "insert into children values(11,'dfgdf',20)");
	i = mysql_query(&my_connection,"select * from children");
    if(i != 0 )
    {
        printf("Update SQL fail %s \n",mysql_error(&my_connection));
        return;
    }else{
        printf("Update SQL success\n");
    }
    MYSQL_RES *res = mysql_store_result(&my_connection);//返回结果集放入MYSQL_RES中
    int num_fields = mysql_num_fields(res);//查看结果集中行数
    MYSQL_ROW row;
    while((row = mysql_fetch_row(res)))//检索一个结果集合的下一行。当在mysql_store_result()之后使用时，
    //没有更多的行可检索时，mysql_etch_row()返回NULL
    {
        int i;
        for(i=0;i<num_fields;i++)
        {
            printf("%s\t",row[i]);
        }
        printf("\n");
    }
    mysql_free_result(res);//必须清空结果集########
	printf("inserted %lu rows",mysql_affected_rows(&my_connection));
}