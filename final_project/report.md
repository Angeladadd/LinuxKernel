# <center>Linux Kernel Final Report</center>

<center>孙晨鸽 516030910421</center>

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

  - [实验平台](#%E5%AE%9E%E9%AA%8C%E5%B9%B3%E5%8F%B0)
  - [第一部分实验](#%E7%AC%AC%E4%B8%80%E9%83%A8%E5%88%86%E5%AE%9E%E9%AA%8C)
    - [实验思路](#%E5%AE%9E%E9%AA%8C%E6%80%9D%E8%B7%AF)
    - [实验过程](#%E5%AE%9E%E9%AA%8C%E8%BF%87%E7%A8%8B)
    - [实验效果](#%E5%AE%9E%E9%AA%8C%E6%95%88%E6%9E%9C)
  - [第二部分实验](#%E7%AC%AC%E4%BA%8C%E9%83%A8%E5%88%86%E5%AE%9E%E9%AA%8C)
    - [实验思路](#%E5%AE%9E%E9%AA%8C%E6%80%9D%E8%B7%AF-1)
    - [实验过程](#%E5%AE%9E%E9%AA%8C%E8%BF%87%E7%A8%8B-1)
    - [实验效果](#%E5%AE%9E%E9%AA%8C%E6%95%88%E6%9E%9C-1)
  - [实验感想](#%E5%AE%9E%E9%AA%8C%E6%84%9F%E6%83%B3)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## 实验平台

* 内核版本 ： 5.5.9
* 平台: 华为云 x 鲲鹏通用计算增强型 | kc1.large.2 | 2vCPUs | 4GB x Ubuntu 18.04 64bit with ARM

## 第一部分实验

### 实验思路

1. **proc**：编写内核模块创建proc文件，通过向proc文件写pid，告诉内核模块统计该pid对应的进程的页热度信息。
2. **对vma进行逻辑划分**：找出**数据段**对应的vma范围，选择数据段区间内的vma，作为筛选出的vma，通过观察benchmark代码，数据存放在通过malloc申请的内存中，即在堆中存放，对应的vma为**brk段**。
3. **迭代统计**：使用**计时器**，每固定时间间隔后，对pid对应的进程进行一次页热度统计，并将热度信息打印在内核态。
4. **统计信息的存储与更新**：通过五次也表转换得到页面并得到上一间隔的统计信息后，将(页虚拟地址，热度)存在内核模块的**可扩展数组**中。

### 实验过程
1. 创建可读写的/proc文件：```/proc/kpage_heat```
   
   通过向/proc/kpage_heat写入pid
   
   ```c
   static int p_id = -1;
   static ssize_t input_pid(struct file *file, const char __user *ubuf,
    size_t count, loff_t *ppos) {
        char *buf = NULL;
        if (*ppos > 0) 
            goto eout;
        buf = (char*) kzalloc(sizeof(char) * count, GFP_KERNEL);
	    if (copy_from_user(buf, ubuf, count)) 
            goto eout;
	    sscanf(buf, "%d", &p_id);
	    printk("input pid: %d\n", p_id);
	    *ppos = strlen(buf);
	    kfree(buf);
	    return *ppos;
    eout:
	    if (buf) kfree(buf);
	    return -EFAULT;
    }
   ```
   
2. 设置计时器，启动内核进程的监控并对进程进行迭代统计
   
   linux kernel中的计时器在```#include <linux/timer.h>```中定义。

   ```c
   #define TIME_INTERVAL 100000
   
   static struct timer_list stimer;

   //计时器回调函数
   static void time_handler(struct timer_list *t)
    { 
        //使用micro second设置超时时间
        mod_timer(&stimer, jiffies + usecs_to_jiffies(TIME_INTERVAL));
        //调用页热度统计函数
        heat(); 
    }
   static int __init my_proc_init(void) {
	    ...
        //初始化计时器，设置计时器的回调函数
        timer_setup(&stimer, time_handler, 0);
        //向计时器链表添加计时器
        add_timer(&stimer);
	    ...
    }

   static void __exit my_proc_exit(void) {
	    ...
        //删除计时器
	    del_timer(&stimer);
    }
   ```
3. 通过pid获取进程描述符，进而获取内存描述符
   
   ```c
   //p_id -> struct pid -> struct task_struct 
    static struct task_struct * get_task_struct_from_pid(int p_id) {
	    struct pid *pid_struct = NULL;
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
    static void heat(void) {
	    ...
	    struct task_struct * task = NULL;
	    struct mm_struct * mm = NULL;
        ...
	    task = get_task_struct_from_pid(p_id);
        ...
	    mm = task->mm;
	    //内核线程的mm字段为空，内存描述符在active_mm字段中
	    if (!mm && !(mm = task->active_mm)) {
		    printk("cannot find mm\n");
		    return;
	    }
	    ...
    }
   ```
4. 找出数据段对应的vma列表

    进程地址空间从低地址开始依次是代码段(Text)、数据段(Data)、BSS段、堆、内存映射段(mmap)、栈。

    <img src="pic/1.jpg" width=500>

    在内存描述符中，分别用

   ```c
	unsigned long start_code, end_code, start_data, end_data;
	unsigned long start_brk, brk, start_stack;
	unsigned long arg_start, arg_end, env_start, env_end;
   ```
   
   这些字段来存储这些段的范围。
   
   	根据benchmark中的两个程序，我们可以看到before和after的数组都是通过malloc申请的，数据储存在堆中，我们就将brk字段对应的区间内的vma作为筛选的vma。
   	
   	```c
   	static struct vm_area_struct * find_heap_vma(struct mm_struct *mm, int * len) {
   		unsigned long start, end;
		printk("-------heap--------\n");
		*len = 0;
		spin_lock(&mm->arg_lock);
		start = mm->start_brk;
		end = mm->brk;
		printk("brk start 0x%lx, end 0x%lx", start, end);
		spin_unlock(&mm->arg_lock);
		return find_segment_vma(mm, len, start, end);
	}
	static struct vm_area_struct * find_segment_vma(struct mm_struct *mm, 
	int * len, unsigned long start, unsigned long end) {
		struct vm_area_struct *head = NULL, *vma = NULL;
		for (vma = mm->mmap; vma && vma->vm_start < start; vma = vma->vm_next)
		{ }
		if (vma && vma->vm_end <= end) {
			head = vma;
		}
		else {
			head = NULL;
		}
		for (;vma && vma->vm_end <= end; vma = vma->vm_next) {
			(*len)++;
		} 
		print_vma(mm, head, *len);
		return head;
	}
   	```
   
5. 将一个vma结构对应的所有页面，通过五次页表转换得到页表项

	由于一个vma对应多个页，我们需要按页对vma进行拆分，后面的五级页表转换和project3是一样的。
	
	```c
	static int count_heat_core(void * data) {
		unsigned long long addr;
		pte_t * pte, pte_v;
		pgd_t * pgd = NULL;
		p4d_t * p4d = NULL;
		pud_t * pud = NULL;
		pmd_t * pmd = NULL;
		spinlock_t *ptl;
		struct count_heat_info * info = (struct count_heat_info *)data;

		printk("updating\n");
	
		addr = info->start;
		while (addr < info->end) {
			pgd = pgd_offset(info->mm, addr);
			if (pgd_none(*pgd) || pgd_bad(*pgd)) {
				printk("vaddr 0x%llx pgd not present.\n", addr);
				goto next;
			}
			p4d = p4d_offset(pgd, addr);
       	 	if (p4d_none(*p4d) || p4d_bad(*p4d)) {
				printk("vaddr 0x%llx p4d not present.\n", addr);
				goto next;
			}
			pud = pud_offset(p4d, addr);
        		if (pud_none(*pud) || pud_bad(*pud)) {
				printk("vaddr 0x%llx pud not present.\n", addr);
				goto next;
			}	
			pmd = pmd_offset(pud, addr);
        		if (pmd_none(*pmd) || pmd_bad(*pmd)) {
				printk("vaddr 0x%llx pmd not present.\n", addr);
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
	```
		
6. 根据pte\_young判断是否在上次间隔访问，使用pte\_mkold重置，使用set\_pte\_at更新页表项

	代码已在第5步中展示，不做赘述。
		
7. 在页热度数组中查找页虚拟地址对应的项，更新页热度

	我们可以实现一个可扩展的数组，存储页热度信息，数组中元素的结构为（虚拟地址，热度计数），我们使用
	
	```c
	struct page_heat {
		unsigned long long v_addr;
		int heat;
	};
	static struct page_heat * page_heat_arr = NULL;
	static int page_heat_arr_capacity = 0;
	static int page_heat_arr_size = 0;
	```
	
	来维护这个数组。
	并且可以通过以下函数来对这个数组进行操作。
	
	```c
	static void append_heat(unsigned long long vaddr);//添加元素
	static void update_heat(unsigned long long vaddr);//更新元素
	static struct page_heat * find_heat(unsigned long long vaddr)；//查找元素
	static void free_heat(void);//清空数组
	```
8. 统计页热度为(热度, 页面数)

	由于进程的数据页比较多，我们将热度信息打印为
	
	```
	HEAT 0 PAGE x
	HEAT 1 PAGE y
	...
	HEAT MAX PAGE z
	```
	的格式。

### 实验效果

修改```benchmark/heat_rand.cpp```，
在运行过程中获取heat\_rand的pid，并写入```/proc/kpage_heat```，
使内核进程可以监控heat\_rand的页热度。

```cpp
//benchmark/heat_rand.cpp
int main(int argc, char *argv[]) {
    ...
    pid_t pid;
    pid = getpid();
    printf("pid %d\n", pid);
    cmd = new char[80];
    sprintf(cmd, "echo %d > /proc/kpage_heat", int(pid));
    if(system(cmd))
        return 0;
    heat();
    ...
}
```

运行```benchmark/heat_rand 8``` ，
通过```dmesg```查看打印在内核态的监控结果：

1. 内核打印heat\_rand进程的页热度信息

    <img src = "pic/2.png" width=400/>
2. 数组起始地址和终止地址在筛选的vma起始地址和终止地址范围内

    <img src = "pic/3.png" width=400/>

    其中由于heat\_rand申请的虚拟地址是连续的，我们只打印了start其实也包括end，可以看到是在我们筛选的范围中的。

3.  筛选出vma结构的page数占整个程序的page数不超过40%

    <img src = "pic/4.png" width=200/>

    其中38701/150676 = 26% < 40%

4.  打印出程序每次迭代的时间，页面收集的时间

    <img src = "pic/5.png" width=400/>

5. 在内核态打印热度信息

    <img src = "pic/6.png" width=150/>
    <img src = "pic/7.png" width=150/>
    <img src = "pic/8.png" width=150/>

## 第二部分实验

### 实验思路

1. 使用一个可读写的proc文件，可以写入监控进程的pid，读出监控进程的页热度信息，并在用户态程序运行前安装好内核模块。
2. 修改用户态进程，在用户态进程开始时，执行```echo <pid> > /proc/kpage_heat```的系统命令。
3. 在用户态进程结束时，执行```cat /proc/kpage_heat```的系统命令。

### 实验过程

1. 设置内核态程序，/proc文件的读、写程序

    ```c
    static struct file_operations my_ops = {
	    .owner = THIS_MODULE,
	    .write = input_pid, //从用户态读入p_id: echo <pid> > /proc/kpage_heat
	    .read = output_result, //用户态读取heat_arr中的热度信息：cat /proc/kpage_heat
    };  

    //input_pid在第一部分已经实现

    ssize_t output_result(struct file *file, char __user *ubuf, 
    size_t count, loff_t *ppos) {
	   //格式化heat_arr到tmp_buf
       ...
	    len += sprintf(buf, "%s\n", tmp_buf);
	    if (copy_to_user(ubuf, buf, len)) {
		    ...
		    return -EFAULT;
	    }
	    *ppos = len;
        ...
	    return *ppos;
    }
    ```
1. 修改用户态进程
   1. 在调用```heat()```之前执行系统命令```echo <pid> > /proc/kpage_heat```
   2. 调用```heat()```  后，睡眠1s，调用命令```cat /proc/kpage_heat```

    ```cpp
    int main(int argc, char *argv[]){
	    //init 
        ...

	    pid_t pid;
        pid = getpid();
        printf("pid %d\n", pid);
	    cmd = new char[80];
	    sprintf(cmd, "echo %d > /proc/kpage_heat", int(pid));
	    if(system(cmd)) 
	    	return 0;
  	    heat();
	    sleep(1);
	    sprintf(cmd, "cat /proc/kpage_heat");
	    if(system(cmd)) 
	    	return 0;
	    delete cmd;
    
        return 0;
    }
    ```

### 实验效果

安装内核模块，运行```./benchmark/heat_rand 8```和```./benchmark/heat 8```，

其中heat， heat\_rand的参数对应程序中的nx，主要影响访存的大小，我们参照程序中的NX给出8这个值。

我们可以看到运行```./benchmark/heat_rand 8```后的热度信息打印在用户态：

<img src = "pic/9.png" width=200/>
<img src = "pic/10.png" width=200/>
<img src = "pic/11.png" width=200/>
<img src = "pic/12.png" width=200/>

可以看到，热度较低处、中等处、较高均有较多页面分布，可以看出这是一个访存不均的程序。

我们可以看到运行```./benchmark/heat 8```后的热度信息打印在用户态：

<img src = "pic/13.png" width=200/>
<img src = "pic/14.png" width=200/>
<img src = "pic/15.png" width=200/>

我们可以看到大部分页面热度在42-44区间，
定性的分析，可以看出heat程序是访存均匀程序。

这里存在两个问题，这里给出可能性较大的原因：
1. 热度分布较大：页热度的统计是由定时器触发的，存在这一页没有访问完，标识位就被置空，进而重复统计的现象。
2. 100次迭代，但大多数页面热度分布在40多：定时器触发的间隔与用户态程序运行的迭代时间存在差异，由于pte_young返回布尔值，不返回次数，存在将两轮迭代统计为一轮的情况。

## 实验总结

Final Project的模块功能比较复杂，因此在课上讲的知识上做了一些补充学习，比如定时器、数据段等等，在实验过程中也发现了dmesg的各种用法，比如实时监控```dmesg -wH```。因为实验要求写的比较意识流，细节比较少，需要自己实验和探索的东西比较多，尝试了很多失败的版本，最终完成了实验检查的功能上的要求，**完成了实验检查的各项要求并能成功统计benchmark程序的页热度信息**。但在性能上依旧存在不足。

## 实验感想

本科期间真正的最后一次课程到此就要结束了，很幸运在最后的这半年选择了Linux内核这门课，确实学到了很多，是我选过的最能锻炼人阅读代码能力、工程时间能力的专业选修课程。感谢陈老师的教导和助教学姐的帮助。