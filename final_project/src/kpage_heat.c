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
#include <linux/delay.h> 

static struct proc_dir_entry *entry = NULL;
static int p_id = -1;

struct page_heat {
	unsigned long v_addr;
	int heat;
};

static struct page_heat * page_heat_arr = NULL;
static int page_heat_arr_capacity = 0;
static int page_heat_arr_size = 0;

/****used for page_heat****/
static void print_heat(void) {
	int i;
	for (i=0;i<page_heat_arr_size;i++) {
		printk("vaddr 0x%lx, heat %d \n", page_heat_arr[i].v_addr, page_heat_arr[i].heat);
	}
}

static void append_heat(unsigned long vaddr) {
	static struct page_heat * tmp = NULL;
	int i;

	if (page_heat_arr_capacity == 0) {
		page_heat_arr_capacity = 1;
		page_heat_arr = (struct page_heat *) kzalloc(page_heat_arr_capacity * sizeof(struct page_heat), GFP_KERNEL);
	}
	if (page_heat_arr_size == page_heat_arr_capacity) {
		page_heat_arr_capacity <<= 1;
		tmp = page_heat_arr;
		page_heat_arr = (struct page_heat *)kzalloc(page_heat_arr_capacity * sizeof(struct page_heat), GFP_KERNEL);
		for (i=0;i<page_heat_arr_size;i++) {
			page_heat_arr[i] = tmp[i];
		}
		kfree(tmp);
	} 
	page_heat_arr[page_heat_arr_size].v_addr = vaddr;
	page_heat_arr[page_heat_arr_size].heat = 1;
	page_heat_arr_size++;
	
}
static void free_heat(void) {
	if (page_heat_arr)
		kfree(page_heat_arr);
	page_heat_arr_capacity = 0;
	page_heat_arr_size = 0;
	page_heat_arr = NULL;
}
static struct page_heat * find_heat(unsigned long vaddr) {
	int i;
	for (i=0;i<page_heat_arr_size;i++) {
		if (page_heat_arr[i].v_addr == vaddr) 
			return &page_heat_arr[i];
	}
	return NULL;
}
static void update_heat(unsigned long vaddr) {
	struct page_heat * heat = find_heat(vaddr);
	if (heat) {
		heat->heat++;
	} else {
		append_heat(vaddr);
	}
}
/*********/



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


/*****find data/heap vma*****/
static struct vm_area_struct * find_segment_vma(struct mm_struct *mm, int * len, unsigned long start, unsigned long end) {
	struct vm_area_struct *head = NULL, *vma = NULL;
	
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

static struct vm_area_struct * find_data_vma(struct mm_struct *mm, int * len) {
	unsigned long start, end;

	*len = 0;
	spin_lock(&mm->arg_lock);
	start = mm->start_data;
	end = mm->end_data;
	printk(KERN_DEBUG "data start 0x%lx, end 0x%lx", start, end);
	spin_unlock(&mm->arg_lock);

	return find_segment_vma(mm, len, start, end);
}

static struct vm_area_struct * find_heap_vma(struct mm_struct *mm, int * len) {
	unsigned long start, end;

	*len = 0;
	spin_lock(&mm->arg_lock);
	start = mm->start_brk;
	end = mm->brk;
	printk(KERN_DEBUG "brk start 0x%lx, end 0x%lx", start, end);
	spin_unlock(&mm->arg_lock);

	return find_segment_vma(mm, len, start, end);
}
/**********/


/*******get page heat*******/
static pte_t * vaddr_to_pte(unsigned long addr, struct mm_struct * mm) {
	pgd_t * pgd = NULL;
	p4d_t * p4d = NULL;
	pud_t * pud = NULL;
	pmd_t * pmd = NULL;
	pte_t * pte = NULL;

	if (!mm && !(mm=task->active_mm)) {
		goto rtn;
	}

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd)) {
		printk("vaddr 0x%lx pgd not present.\n", addr);
		goto rtn;
	}
	p4d = p4d_offset(pgd, addr);
        if (p4d_none(*p4d) || p4d_bad(*p4d)) {
		printk("vaddr 0x%lx p4d not present.\n", addr);
		goto rtn;
	}
	pud = pud_offset(p4d, addr);
        if (pud_none(*pud) || pud_bad(*pud)) {
		printk("vaddr 0x%lx pud not present.\n", addr);
		goto rtn;
	}
	pmd = pmd_offset(pud, addr);
        if (pmd_none(*pmd) || pmd_bad(*pmd)) {
		printk("vaddr 0x%lx pmd not present.\n", addr);
		goto rtn;
	}
	pte = pte_offset_kernel(pmd, addr);
	if (!pte_present(*pte)) {
//		printk("vaddr 0x%lx pte not present.\n", addr);
		goto rtn;
	}
rtn:
	return pte;
}

static void count_heat(unsigned long start, unsigned long end, struct mm_struct * mm) {
	unsigned long addr = start;
	pte_t * pte, pte_v;
	while (addr <= end) {
		pte = vaddr_to_pte(addr, mm);
		if (pte && pte_young(*pte)) {
			update_heat(addr);
			pte_v = *pte;
			pte_mkold(pte_v);
			set_pte_at(mm, addr, pte, pte_v);
		}
		addr += PAGE_SIZE;
	}
}
/*************/


static void print_vma(struct mm_struct * mm, struct vm_area_struct * vma, int len) {
	int i;
	down_read(&mm->mmap_sem); 
	for (; len>0 && vma; len--, vma = vma->vm_next) {  
		printk("VMA 0x%lx-0x%lx", vma->vm_start, vma->vm_end);  
		printk("\n");  
	}
	up_read(&mm->mmap_sem); 
	for(i=0;i<5;i++) {
		count_heat(vma->vm_start, vma->vm_end, mm);
		msleep(1);
	}
}

static void page_heat(int p_id) {
	struct vm_area_struct *vma;
	int len;
	struct task_struct * task = NULL;
	struct mm_struct * mm = NULL;

	printk(KERN_DEBUG "pid: %d", p_id);
	task = get_task_struct_from_pid(p_id);
	if (!task) {
		printk(KERN_DEBUG "cannot find task from pid\n");
		return;
	}
	//while(1) {
		//user level thread
		mm = task->mm;
		//kernel level thread
		if (!mm && !(mm = task->active_mm)) {
			printk(KERN_DEBUG "cannot find mm\n");
			return;
		}

		printk(KERN_DEBUG "get mm\n");

		printk("part 3.1.1-------find vmas-------\n");
		// vma = find_data_vma(mm, &len);
		// printk("-------data--------\n");
		// print_vma(mm, vma, len);
		vma = find_heap_vma(mm, &len);
		printk("-------heap--------\n");
		print_vma(mm, vma, len);

		printk("part 3.1.2-------find pages---------\n");
		printk("total pages = %d\n", mm->total_vm);
		printk("selected pages = %d\n", page_heat_arr_size);

		printk("part 3.1.3-------print time&heat---------\n");
		print_heat();

	//}	
	free_heat();
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
