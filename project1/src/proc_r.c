/* lab1 module3
 * read-only proc file
 * @author: chenge.sun(516030910421)
 */

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>

#define BUFSIZE 80

static struct proc_dir_entry *entry = NULL;
static const char content[BUFSIZE] = "Message from read-only proc file";

static ssize_t my_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos) {
	char buf[BUFSIZE];
	int len = 0;
	printk(KERN_DEBUG "[module3] reading...\n");
	if (*ppos > 0 || count < BUFSIZE)
		return 0;
	len += sprintf(buf, "%s\n", content);
	if (copy_to_user(ubuf, buf, len))
		return -EFAULT;
	*ppos = len;
	return len;
}

static const struct file_operations my_ops = {
	.owner = THIS_MODULE,
	.read = my_read,
};	

static int __init my_proc_init(void)
{
	entry = proc_create("proc_r", 0444, NULL, &my_ops);
	if (!entry)
		return -1;
	else {
		printk(KERN_INFO "[module3] hello read-only proc file\n");
		return 0;
	}
}
static void __exit my_proc_exit(void) {
	proc_remove(entry);
	printk(KERN_INFO "[module3] goodbye read-only proc file\n");
}

module_init(my_proc_init);
module_exit(my_proc_exit);
