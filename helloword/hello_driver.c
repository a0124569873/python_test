#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
static int __init hello_init(void)
{
      printk(KERN_ALERT "hello driver init!\n");
      return 0;
}

static void __exit hello_exit(void)
{
       printk(KERN_ALERT "hello driver exit\n");
}
module_init(hello_init);
module_exit(hello_exit);
