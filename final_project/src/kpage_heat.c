#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <asm/io.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>

static struct proc_dir_entry *entry = NULL;
static int p_id = -1;

static struct task_struct * get_task_struct_from_pid(int p_id) {
	struct pid *pid_struct;
	struct task_struct *task = NULL;
	pid_struct = find_get_pid(p_id);
	if (!pid_struct) {
		printk(KERN_DEBUG "pid not found\n");
		goto out;
	}
	task = pid_task(pid_struct, PIDTYPE_PID);
	if (!task)
		printk(KERN_DEBUG "task not found\n");
out:
	return task;
}

static struct vm_area_struct * find_data_vma(struct mm_struct *mm, int * len) {
	struct vm_area_struct * head;
	unsigned long start, end;
	struct vm_area_struct *vma;

	*len = 0;
	spin_lock(&mm->arg_lock);
	start = mm->start_data;
	end = mm->end_data;
	printk(KERN_DEBUG "data start 0x%lx, end 0x%lx", start, end);
	spin_unlock(&mm->arg_lock);

	down_read(&mm->mmap_sem); 
	for (vma = mm->mmap; vma && vma->vm_start < start; vma = vma->vm_next) { }
	if (vma && vma->vm_end <= end) {
		head = vma;
	}
	else {
		head = NULL;
	}
	for (;vma && vma->vm_end <= end; vma = vma->vm_next) {
		(*len)++;
	}
	up_read(&mm->mmap_sem); 
	return head;
}

static struct vm_area_struct * find_heap_vma(struct mm_struct *mm, int * len) {
	struct vm_area_struct * head;
	unsigned long start, end;
	struct vm_area_struct *vma;

	*len = 0;
	spin_lock(&mm->arg_lock);
	start = mm->start_brk;
	end = mm->brk;
	spin_unlock(&mm->arg_lock);

	down_read(&mm->mmap_sem); 
	for (vma = mm->mmap; vma && vma->vm_start < start; vma = vma->vm_next) { }
	if (vma && vma->vm_end <= end) {
		head = vma;
	}
	else {
		head = NULL;
	}
	for (;vma && vma->vm_end <= end; vma = vma->vm_next) {
		(*len)++;
	}
	up_read(&mm->mmap_sem); 
	return head;
}

static void page_heat(int p_id) {
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	int len;

	printk(KERN_DEBUG "pid: %d", p_id);
	task = get_task_struct_from_pid(p_id);
	if (!task) {
		return;
	}
	mm = task->mm;
	vma = find_data_vma(mm, &len);
	printk("-------data--------\n");
	down_read(&mm->mmap_sem); 
	for (; len>0 && vma; len--, vma = vma->vm_next) {  
		printk("VMA 0x%lx-0x%lx", vma->vm_start, vma->vm_end);  
		printk("\n");  
	}
	up_read(&mm->mmap_sem); 
	vma = find_heap_vma(mm, &len);
	printk("-------heap--------\n");
	down_read(&mm->mmap_sem); 
	for (; len>0 && vma; len--, vma = vma->vm_next) {  
		printk("VMA 0x%lx-0x%lx", vma->vm_start, vma->vm_end);  
		printk("\n");  
	}
	up_read(&mm->mmap_sem); 	
}

static ssize_t input_pid(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) {
	char *buf = NULL;
	if (*ppos > 0) 
		goto eout;
	buf = (char*) kzalloc(sizeof(char) * count, GFP_KERNEL);
	if (copy_from_user(buf, ubuf, count)) 
		goto eout;

	sscanf(buf, "%d", &p_id);
	page_heat(p_id);
	*ppos = strlen(buf);
	kfree(buf);
	return *ppos;
eout:
	if (buf) kfree(buf);
	return -EFAULT;
}

static struct file_operations my_ops = {
	.owner = THIS_MODULE,
	.write = input_pid,
};

static int __init my_proc_init(void) {
	entry = proc_create("kpage_heat", 0660, NULL, &my_ops);
	return entry?0:-1;
}

static void __exit my_proc_exit(void) {
	proc_remove(entry);
}

MODULE_LICENSE("GPL");

module_init(my_proc_init);
module_exit(my_proc_exit);