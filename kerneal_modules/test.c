#include <linux/init.h>
#include <linux/module.h>
MODULE_LICENSE("Dual BSD/GPL");

static int hello_init(void){
    printk(KERN_ALERT "hello word\n");
    return 0;
}
static int hello_exit(void){
    printk(KERN_ALERT "good bye\n");
}
module_init(hello_init);
module_exit(hello_exit);