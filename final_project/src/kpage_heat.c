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
#include <linux/ktime.h> 
#include <linux/timer.h>
#include <linux/kthread.h>

#define TIME_INTERVAL 1
#define HEAT_MAX 200
#define THREAD_NUM 8
#define LINE_LEN 80

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

static int heat_arr[HEAT_MAX+1];
static int size;

static void print_heat(void) {
	int i;
	int max_heat = 0, min_heat = __INT_MAX__;

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
	page_heat_arr_capacity = 0;
	page_heat_arr_size = 0;
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
		printk("pid not found\n");
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
	printk("data start 0x%lx, end 0x%lx", start, end);
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
	printk("brk start 0x%lx, end 0x%lx", start, end);
	spin_unlock(&mm->arg_lock);

	return find_segment_vma(mm, len, start, end);
}
/**********/


/*******get page heat*******/

static struct count_heat_info {
	unsigned long long start;
	unsigned long long end;
	struct mm_struct * mm;
};

static int count_heat_core(void * data) {
	unsigned long long addr;// = info->start;
	pte_t * pte, pte_v;
	pgd_t * pgd = NULL;
	p4d_t * p4d = NULL;
	pud_t * pud = NULL;
	pmd_t * pmd = NULL;
	spinlock_t *ptl;
	struct count_heat_info * info = (struct count_heat_info *)data;

	// printk("updating\n");
	
	addr = info->start;
	while (addr < info->end) {
		pgd = pgd_offset(info->mm, addr);
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
		pte = pte_offset_map_lock(info->mm, pmd, addr, &ptl);
		if (pte && pte_present(*pte) && pte_young(*pte)) {
			pte_v = *pte;
			pte_v = pte_mkold(pte_v);
			set_pte_at(info->mm, addr, pte, pte_v);
			update_heat(addr);
			hot_page_number++;
		}
		pte_unmap_unlock(pte, ptl);
next:
		addr += PAGE_SIZE;
	}
	return 0;
}

static void count_heat(struct mm_struct * mm, struct vm_area_struct * vma, int len) {
	// printk("counting heat...\n");
	int step, i, page_num;//, start[THREAD_NUM], end[THREAD_NUM];
	struct count_heat_info info[THREAD_NUM];
	char thread_name[THREAD_NUM][80];
	for (i=0;i<THREAD_NUM;i++) {
		sscanf(thread_name[i], "count heat core %d\0", i);
	}
	for (; len>0 && vma; len--, vma = vma->vm_next) {  
		page_num = (vma->vm_end - vma->vm_start)/PAGE_SIZE;
		step = page_num/THREAD_NUM * PAGE_SIZE;
		for (i=0;i<THREAD_NUM;i++) {
			info[i].start = (i == 0)?0:info[i-1].end;
			info[i].end = (i == THREAD_NUM - 1)?vma->vm_end:info[i].start + step;
			info[i].mm = mm;
			kthread_run(count_heat_core, &(info[i]), thread_name[i]);
		}
	}
}
/*************/

static void heat(void) {
	struct vm_area_struct *vma;
	int len;
	struct task_struct * task = NULL;
	struct mm_struct * mm = NULL;
	int i=0;
	struct timeval start, finish;

	start = ktime_to_timeval(ktime_get());
	hot_page_number = 0;
	if(p_id == -1) {
		printk("no pid\n");
		return;
	}

	if (last_p_id != p_id) {
		printk("free page heat arr\n");
		free_heat();
	}

	last_p_id = p_id;

	//printk("pid: %d", p_id);
	//printk("last_pid: %d", last_p_id);
	task = get_task_struct_from_pid(p_id);
	if (!task) {
		printk("cannot find task from pid\n");
		p_id = -1;
		last_p_id = -1;
		printk("pid %d", p_id);
		return;
	}
	mm = task->mm;
	//kernel level thread
	if (!mm && !(mm = task->active_mm)) {
		printk("cannot find mm\n");
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
	finish = ktime_to_timeval(ktime_get());
	printk("collecting time: %lld micro seconds\n", ((finish.tv_sec * 1000000) + finish.tv_usec) - ((start.tv_sec * 1000000) + start.tv_usec));
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

ssize_t output_result(struct file *file, char __user *ubuf, size_t count, loff_t *ppos) {
	char buf[LINE_LEN * (HEAT_MAX+1)];
	int pos = 0;
	int i=0, j=0;
	char tmp[LINE_LEN];
	if (*ppos > 0)
		return 0;
	for (i=0;i<=size;i++) {
		sprintf(tmp, "HEAT %d PAGE %d\n", i, heat_arr[i]);
		for (j=0;j<strlen(tmp);j++) {
			buf[pos] = tmp[j];
			pos++;
		}
	}
	buf[pos] = '\0';
	if (copy_to_user(ubuf, &buf, pos+1)) {
		return -EFAULT;
	}
	*ppos = pos+1;
	return *ppos;
}

static struct file_operations my_ops = {
	.owner = THIS_MODULE,
	.write = input_pid,
	.read = output_result,
};

static void time_handler(struct timer_list *t)
{ 
	//printk("timer\n");
    mod_timer(&stimer, jiffies + TIME_INTERVAL*HZ);
    heat(); 
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
