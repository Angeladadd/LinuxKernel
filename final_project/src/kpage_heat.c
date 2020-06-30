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
#include <linux/ktime.h> 
#include <linux/timer.h>

#define TIME_INTERVAL 5
#define HEAT_MAX 200

static struct proc_dir_entry *entry = NULL;
static int p_id = -1;
static int last_p_id = -1;
static int hot_page_number = 0;

static struct timer_list stimer; 

struct page_heat {
	unsigned long long v_addr;
	int heat;
};

static struct page_heat * page_heat_arr = NULL;
static int page_heat_arr_capacity = 0;
static int page_heat_arr_size = 0;

static void print_heat(void) {
	int i;
	int max_heat = 0, min_heat = __INT_MAX__;
	int heat_arr[HEAT_MAX+1];
	int size;

	for (i=0;i<=HEAT_MAX;i++) {
		heat_arr[i] = 0;
	}
	for (i=0;i<page_heat_arr_size;i++) {
		max_heat = max(max_heat, page_heat_arr[i].heat);
		min_heat = min(min_heat, page_heat_arr[i].heat);
		if (page_heat_arr[i].heat >= HEAT_MAX) {
			heat_arr[HEAT_MAX]++;
			continue;
		}
		heat_arr[page_heat_arr[i].heat]++;
	}
	printk("--------page heat-------\n");
	printk("MIN %d\n", min_heat);
	printk("MAX %d\n", max_heat);

	size = min(max_heat, HEAT_MAX);

	for (i=0;i<=size;i++) {
		printk("HEAT %d PAGE %d\n", i, heat_arr[i]);
	}
}

static void append_heat(unsigned long long vaddr) {
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
}
static struct page_heat * find_heat(unsigned long long vaddr) {
	int i;
	for (i=0;i<page_heat_arr_size;i++) {
		if (page_heat_arr[i].v_addr == vaddr) 
			return &page_heat_arr[i];
	}
	return NULL;
}
static void update_heat(unsigned long long vaddr) {
	struct page_heat * heat = find_heat(vaddr);
	if (heat) {
		heat->heat++;
	} else {
		append_heat(vaddr);
	}
}

static struct task_struct * get_task_struct_from_pid(int p_id) {
	struct pid *pid_struct;
	struct task_struct *task = NULL;
	pid_struct = find_get_pid(p_id);
	if (!pid_struct) {
		printk(KERN_DEBUG "pid not found\n");
		goto out;
	}
	task = pid_task(pid_struct, PIDTYPE_PID);
out:
	return task;
}


/*****find data/heap vma*****/
static void print_vma(struct mm_struct * mm, struct vm_area_struct * vma, int len) {
	// down_read(&mm->mmap_sem); 
	for (; len>0 && vma; len--, vma = vma->vm_next) {  
		printk("VMA 0x%lx-0x%lx", vma->vm_start, vma->vm_end);  
		printk("\n");  
	}
	// up_read(&mm->mmap_sem); 
}

static struct vm_area_struct * find_segment_vma(struct mm_struct *mm, int * len, unsigned long start, unsigned long end) {
	struct vm_area_struct *head = NULL, *vma = NULL;
	
	// down_read(&mm->mmap_sem); 
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
	// up_read(&mm->mmap_sem); 

	print_vma(mm, head, *len);

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

	printk("-------heap--------\n");
	*len = 0;
	spin_lock(&mm->arg_lock);
	start = mm->start_brk;
	end = mm->brk;
	//if (print)
	printk(KERN_DEBUG "brk start 0x%lx, end 0x%lx", start, end);
	spin_unlock(&mm->arg_lock);

	return find_segment_vma(mm, len, start, end);
}
/**********/


/*******get page heat*******/

static void count_heat_core(unsigned long long start, unsigned long long end, struct mm_struct * mm) {
	unsigned long long addr = start;
	pte_t * pte, pte_v;
	pgd_t * pgd = NULL;
	p4d_t * p4d = NULL;
	pud_t * pud = NULL;
	pmd_t * pmd = NULL;
	spinlock_t *ptl;

	// printk("updating\n");
	while (addr <= end) {
		pgd = pgd_offset(mm, addr);
		if (pgd_none(*pgd) || pgd_bad(*pgd)) {
			printk("vaddr 0x%lx pgd not present.\n", addr);
			goto next;
		}
		p4d = p4d_offset(pgd, addr);
        if (p4d_none(*p4d) || p4d_bad(*p4d)) {
			printk("vaddr 0x%lx p4d not present.\n", addr);
			goto next;
		}
		pud = pud_offset(p4d, addr);
        if (pud_none(*pud) || pud_bad(*pud)) {
			printk("vaddr 0x%lx pud not present.\n", addr);
			goto next;
		}	
		pmd = pmd_offset(pud, addr);
        if (pmd_none(*pmd) || pmd_bad(*pmd)) {
			printk("vaddr 0x%lx pmd not present.\n", addr);
			goto next;
		}
		pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
		if (pte && pte_present(*pte) && pte_young(*pte)) {
			pte_v = *pte;
			pte_v = pte_mkold(pte_v);
			set_pte_at(mm, addr, pte, pte_v);
			update_heat(addr);
			hot_page_number++;
		}
		pte_unmap_unlock(pte, ptl);
next:
		addr += PAGE_SIZE;
	}
}

static void count_heat(struct mm_struct * mm, struct vm_area_struct * vma, int len) {
	// printk("counting heat...\n");
	for (; len>0 && vma; len--, vma = vma->vm_next) {  
		count_heat_core(vma->vm_start, vma->vm_end, mm);
	}
}
/*************/

static void heat(int p_id) {
	struct vm_area_struct *vma;
	int len;
	struct task_struct * task = NULL;
	struct mm_struct * mm = NULL;
	int i=0;

	hot_page_number = 0;
	if(p_id == -1) {
		printk(KERN_DEBUG "no pid\n");
		return;
	}
	if (last_p_id != p_id) {
		free_heat();
		last_p_id = p_id;
	}

	printk(KERN_DEBUG "pid: %d", p_id);
	task = get_task_struct_from_pid(p_id);
	if (!task) {
		printk(KERN_DEBUG "cannot find task from pid\n");
		p_id = -1;
		last_p_id = -1;
		return;
	}
	mm = task->mm;
	//kernel level thread
	if (!mm && !(mm = task->active_mm)) {
		printk(KERN_DEBUG "cannot find mm\n");
		return;
	}

	printk("part 3.1.1-------find vmas-------\n");
	down_read(&mm->mmap_sem); 
	vma = find_heap_vma(mm, &len);
	count_heat(mm, vma, len);
	up_read(&mm->mmap_sem);

	printk("part 3.1.2-------find pages---------\n");
	printk("total pages = %d\n", (int)mm->total_vm);
	printk("selected pages = %d\n", hot_page_number);

	printk("part 3.1.3-------print time&heat---------\n");
	print_heat();
	printk("collecting time:xxx\n");
}

static ssize_t input_pid(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) {
	char *buf = NULL;
	int times = 0;
	if (*ppos > 0) 
		goto eout;
	buf = (char*) kzalloc(sizeof(char) * count, GFP_KERNEL);
	if (copy_from_user(buf, ubuf, count)) 
		goto eout;
	sscanf(buf, "%d", &p_id);
	printk("input pid: %d\n", p_id);
	//heat(p_id);
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

static void time_handler(struct timer_list *t)
{ 
	//printk("timer\n");
    mod_timer(&stimer, jiffies + TIME_INTERVAL*HZ);
    heat(p_id); 
}

static int __init my_proc_init(void) {
	entry = proc_create("kpage_heat", 0660, NULL, &my_ops);
    timer_setup(&stimer, time_handler, 0);
    add_timer(&stimer);
	printk("install kpage_heat\n");
	return entry?0:-1;
}

static void __exit my_proc_exit(void) {
	proc_remove(entry);
	del_timer(&stimer);
}

MODULE_LICENSE("GPL");

module_init(my_proc_init);
module_exit(my_proc_exit);