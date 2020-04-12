/* lab1 module1
 * test for installing and removing of module
 * @author: chenge.sun(516030910421)
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

static int __init hello_init(void)
{
	printk(KERN_INFO "[module1] hello world\n");
	return 0;
}
static void __exit hello_exit(void)
{
	printk(KERN_INFO "[module1] goodbye world\n");
}
module_init(hello_init);
module_exit(hello_exit);
