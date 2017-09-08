#include <stdio.h>  /* 标准输入输出头文件 */
#include <stdlib.h> /* strtoul用到的头文件 */

struct test_pfun                                          { /* 定义一个结构体，里面有三个成员，是三个函数指针 ,前面千万不要加static,这里并没有分配内存*/
int (*add) (int a,int b);
int (*sub) (int a,int b);
int (*mult) (int a,int b);
};

static int  test_add(int a,int b)   /* 定义求和函数 */
{
   return (a+b);
}

static int  test_sub(int a,int b)   /* 定义相减函数 */
{
   return (a-b);
}

static int   test_mult(int a,int b)   /* 定义乘法函数 */
{
   return (a*b);
}

struct test_pfun pfun={    /* 关键的地方时在这里，看怎么函数指针赋值 */
 .add   =test_add,
 .sub   =test_sub,
 .mult  =test_mult,
};

/*
*  usage:
*  ./a.out num1 num2 
*/
void print_uage()
{
   printf("./a.out <num1> <num2>\n ");    /* 打印用法 */
}

int main(int argc,char **argv)
{
   int a ,b;  
   if(argc!=3)
   {
 print_uage();
return -1;
   }
  a=strtoul(argv[1],NULL,0);    /* 把字符串argv[1]转换成一个整数a */
  b=strtoul(argv[2],NULL,0);   /* 把字符串argv[2]转换成一个整数b */

/* 不懂strtoul命令的请点击这里：点击这里！ */
printf("a+b=%d\n",pfun.add(a,b));
printf("a-b=%d\n",pfun.sub(a,b));
printf("a*b=%d\n",pfun.mult(a,b));
   return 0;
}