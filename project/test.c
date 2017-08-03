#include <stdio.h>
int ff(int(*p)(int,int),int a,int b)//原始写法,阅读不便
{
    return p(a,b);
}
typedef int(*Pfun)(int,int);//定义函数指针类型，同时申明了原型 返回int 两个int形参
int f(Pfun p,int a,int b) //改进写法 易懂
{
    return p(a,b);
}
int add(int a,int b)
{
    printf("加法函数add被调用:");
    return a+b;
}
int sub(int a,int b)
{
    printf("减法函数sub被调用:");
    return a-b;
}
int chen(int a,int b){
    printf("cheng is be call:");
    return a*b;
}
void main()
{//函数指针初步应用
    int a=1,b=2;
    printf(" %d+%d=%d\n",a,b,f(add,a,b));
    printf(" %d-%d=%d\n",a,b,f(sub,a,b));
    printf(" %d+%d=%d\n",a,b,ff(add,a,b));
    printf(" %d-%d=%d\n",a,b,ff(sub,a,b));
    printf(" %d-%d=%d\n",a,b,ff(chen,a,b));
}