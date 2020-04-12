/* lab1 module4
 * read-wirte proc file
 * plus: handling buffer overflow by adjusting buffer size
 * @author: chenge.sun(516030910421)
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

static const char* DEFAULT_CONTENT = "default content";
static size_t buffer_size = 100;
static char *buffer = NULL; // will be initialized with "default content"

static struct proc_dir_entry *parent = NULL;
static struct proc_dir_entry *entry = NULL;

static ssize_t my_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) {
	printk(KERN_DEBUG "[module4] writing...\n");
	char *buf = NULL;
	if (*ppos > 0) 
		return -EFAULT;
	if (count > buffer_size) {
		buffer_size = count+1;
		if (buffer) 
			kfree(buffer);
		buffer = (char*) kzalloc(sizeof(char) * buffer_size, GFP_KERNEL);
	}
	buf = (char*) kzalloc(sizeof(char) * buffer_size, GFP_KERNEL);
	if (copy_from_user(buf, ubuf, count)) {
		if (buf) 
			kfree(buf);
		return -EFAULT;
	}
	sscanf(buf, "%s", buffer);
	*ppos = strlen(buf);
	kfree(buf);
	return *ppos;
}

static ssize_t my_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos) {
	printk(KERN_DEBUG "[module4] reading...\n");
	char *buf = NULL;
	int len = 0;
	if (*ppos > 0 || count < buffer_size)
		return 0;
	buf = (char*) kzalloc(sizeof(char) * buffer_size, GFP_KERNEL);
	len += sprintf(buf, "%s\n", buffer);
	if (copy_to_user(ubuf, buf, len)) {
		if (buf)
			kfree(buf);
		return -EFAULT;
	}
	*ppos = len;
	kfree(buf);
	return len;
}

static struct file_operations my_ops = {
	.owner = THIS_MODULE,
	.read = my_read,
	.write = my_write,
};

static int __init my_proc_init(void) {
	parent = proc_mkdir("proc_rw_dir", NULL);
	if (!parent)
		return -1;
	entry = proc_create("proc_rw", 0660, parent, &my_ops);
	if (!entry) 
		return -1;
	printk(KERN_INFO "[module4] hello read-wirte proc file\n");
	buffer = (char*) kzalloc(sizeof(char) * buffer_size, GFP_KERNEL);
	strcpy(buffer, DEFAULT_CONTENT);
	return 0;
}

static void __exit my_proc_exit(void) {
	if (buffer) {
		kfree(buffer);
	}
	proc_remove(entry);
	proc_remove(parent);
	printk(KERN_INFO "[module4] goodbye read-write proc file\n");
}

module_init(my_proc_init);
module_exit(my_proc_exit);
