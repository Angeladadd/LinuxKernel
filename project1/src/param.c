/* lab1 module2
 * support for int&str&array parameter
 * @author: chenge.sun(516030190421)
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/stat.h>

static int int_var = 1;
static char* str_var = "hello";
static int int_arr_var[20]={0};
static int num = 1;

module_param(int_var, int, S_IRUGO);
module_param(str_var, charp, S_IRUGO);
module_param_array(int_arr_var, int, &num, S_IRUGO);

static int __init param_init(void)
{
	int i=0;
	printk(KERN_INFO "[module2] hello param\n");
	printk(KERN_INFO "[module2] int_var is %d;\n", int_var);
	printk(KERN_INFO "[module2] str_var is %s;\n", str_var);
	for(i=0;i<num;i++) {
		printk(KERN_INFO "[module2] int_arr_var[%d]=%d;\n",i, int_arr_var[i]);
	}
	return 0;
}

static void __exit param_exit(void)
{
	printk(KERN_INFO "[module2] goodbye param\n");
}

module_init(param_init);
module_exit(param_exit);
