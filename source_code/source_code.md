# <center>源码阅读</center>

<center>孙晨鸽 516030910421 </center>

* 内核版本 ： 5.5.9

## Linux的I/O多路复用

I/O操作的持续时间通常是不可预知的，这可能和机械装置的情况有关（磁头的当前位置），和实际的随机事件有关（数据包到达时间），和人为因素有关（用户键盘输入）。启动I/O操作的设备驱动程序必须依靠一种监控技术在I/O操作终止或超时时发出信号。

监控I/O操作结束的两种可用的技术分别为：
* 轮询模式
* 中断模式

在实际应用中，应用软件常常需要同时监控若干个I/O通道，等待来自其中任意一个通道的输入数据并作出反应。I/O多路复用通过一种机制，可以监视多个描述符，一旦某个描述符就绪（一般是读就绪或者写就绪），能够通知程序进行相应的读写操作。I/O多路复用技术是为了解决进程或线程阻塞到某个I/O系统调用而出现的技术，使进程不阻塞于某个特定的 I/O 系统调用。

Linux/Unix提供了select/poll/epoll的系统调用来实现I/O多路复用。

```bash
cd /usr/src/linux-5.5.9/fs
ag "SYSCALL.*(select|poll|epoll)" #查看系统调用的位置
```

### select
select是IO多路复用的一种实现，它将需要监控的fd分为读，写，异常三类，使用fd_set表示，当其返回时要么是超时，要么是有至少一种读，写或异常事件发生。
select的系统调用定义在```fs/select.c```中。

```c
SYSCALL_DEFINE5(select, int, n, fd_set __user *, inp, 
fd_set __user *, outp, fd_set __user *, exp, 
struct __kernel_old_timeval __user *, tvp)
{
    return kern_select(n, inp, outp, exp, tvp);
}
```

我们可以看到这个系统调用实际上是函数```kern_select```，
其中表示监控的文件的数据结构是```fd_set``` 在```include/linux/types.h```中定义，实际上是```__kernel_fd_set```，

```c
#define __FD_SETSIZE	1024

typedef struct {
    unsigned long fds_bits[__FD_SETSIZE / (8 * sizeof(long))];
} __kernel_fd_set;
```

可以看到，fd_set实际上是long类型的数组，共1024位，我们可以使用FD_SET设置fd_set:

```c
#define FD_SETSIZE 256

typedef struct { uint32_t fd32[FD_SETSIZE/32]; } fd_set;
//此时的fd_set使用tools/include/nolibc/nolibc.h中的定义
static __attribute__((unused))
void FD_SET(int fd, fd_set *set)
{
    if (fd < 0 || fd >= FD_SETSIZE)
        return;
    set->fd32[fd / 32] |= 1 << (fd & 31);
}
```

我们可以看到FD\_SET是设置fd\_set中的某一位，每一位用来表示一个fd，这也就是select针对读，写或异常每一类最多只能有1024个fd限制的由来。

```c
static int kern_select(
    int n, //n是三类不同的fd_set中所包括的fd数值的最大值+1,
    fd_set __user *inp, //当前进程在睡眠中等待来自哪一些已打开文件的输入
    fd_set __user *outp, //等待哪些文件的写操作
    fd_set __user *exp, //监视哪些通道发生了异常
    //睡眠等待的最长时间，指针为0表示无限期的睡眠等待
    struct __kernel_old_timeval __user *tvp
    )
{
    struct timespec64 end_time, *to = NULL;
    struct __kernel_old_timeval tv;
    int ret;
    //tvp在用户空间，需要使用copy_from_user拷贝到内核
    if (tvp) {
        if (copy_from_user(&tv, tvp, sizeof(tv)))
            return -EFAULT;
        to = &end_time;
        //这里使用poll_select_set_timeout设置timeout的值（其实只是检查一下并拷贝）
        if (poll_select_set_timeout(
            to, //timeout的指针
            tv.tv_sec + (tv.tv_usec / USEC_PER_SEC), //秒
            (tv.tv_usec % USEC_PER_SEC) * NSEC_PER_USEC) //纳秒
            )
            return -EINVAL;
        }
        //核心的功能在core_sys_select中实现
        ret = core_sys_select(n, inp, outp, exp, to);
        //获取当前的时间戳，和传入的时间戳end_time求差值，返回给用户剩余的超时时间
        return poll_select_finish(&end_time, tvp, PT_TIMEVAL, ret);
}
```

可以看到主要的逻辑在```core_sys_select```中，它与系统调用的参数仅有to不同，它本质上是tvp在内核中的拷贝。

fd\_set\_bits包含了in,out,ex的要求（监控）和结果，共6个bitmaps。

```c
typedef struct {
    unsigned long *in, *out, *ex;
    unsigned long *res_in, *res_out, *res_ex;
} fd_set_bits;
```

```c
int core_sys_select(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timespec64 *end_time)
{
    fd_set_bits fds;
    void *bits;
    int ret, max_fds;
    size_t size, alloc_size;
    struct fdtable *fdt;
    long stack_fds[SELECT_STACK_ALLOC/sizeof(long)];
    ret = -EINVAL;
    if (n < 0)
        goto out_nofds;
    //加锁防止max_fds改变
    rcu_read_lock();
    fdt = files_fdtable(current->files);
    max_fds = fdt->max_fds;
    rcu_read_unlock();
    if (n > max_fds)
        n = max_fds;
    /*
     * We need 6 bitmaps (in/out/ex for both incoming and outgoing),
     * since we used fdset we need to allocate memory in units of
     * long-words. 
     */
    size = FDS_BYTES(n);
    bits = stack_fds;
    if (size > sizeof(stack_fds) / 6) {
        /* Not enough space in on-stack array; must use kmalloc*/
        ret = -ENOMEM;
        if (size > (SIZE_MAX / 6))
            goto out_nofds;
        alloc_size = 6 * size;
        bits = kvmalloc(alloc_size, GFP_KERNEL);
        if (!bits)
            goto out_nofds;
    }
    fds.in      = bits;
    fds.out     = bits +   size;
    fds.ex      = bits + 2*size;
    fds.res_in  = bits + 3*size;
    fds.res_out = bits + 4*size;
    fds.res_ex  = bits + 5*size;

    //初始化用作参数的和用作返回值的fd_set
    if ((ret = get_fd_set(n, inp, fds.in)) ||
        (ret = get_fd_set(n, outp, fds.out)) ||
        (ret = get_fd_set(n, exp, fds.ex)))
        goto out;
    zero_fd_set(n, fds.res_in);
    zero_fd_set(n, fds.res_out);
    zero_fd_set(n, fds.res_ex);

//其实上面的一大坨操作都是在拷贝用户空间的fd_set到内核态，
//以及安全性检查、初始化之类的工作，
//最主要的逻辑在do_select中
    ret = do_select(n, &fds, end_time);
    if (ret < 0)
        goto out;
    if (!ret) {
        ret = -ERESTARTNOHAND;
        if (signal_pending(current))
            goto out;
        ret = 0;
    }
    //返回结果复制回用户空间
    if (set_fd_set(n, inp, fds.res_in) ||
        set_fd_set(n, outp, fds.res_out) ||
        set_fd_set(n, exp, fds.res_ex))
        ret = -EFAULT;
out:
    if (bits != stack_fds)
        kvfree(bits);
out_nofds:
    return ret;
}
```

可以看到操作的主体是```do_select```：

```c
static int do_select(
    int n, 
    fd_set_bits *fds, //(res_)(in/out/ex)六个位图
    struct timespec64 *end_time //timeout
    )
{
    ktime_t expire, *to = NULL;
    struct poll_wqueues table;
    poll_table *wait;
    int retval, i, timed_out = 0;
    u64 slack = 0;
    __poll_t busy_flag = net_busy_loop_on() ? POLL_BUSY_LOOP : 0;
    unsigned long busy_start = 0;
    rcu_read_lock();
    //计算出本次操作涉及的最大已打开文件号
    retval = max_select_fd(n, fds);
    rcu_read_unlock();
    if (retval < 0)
        return retval;
    //所有号码高于最大已打开文件号的文件与本次操作无关
    n = retval;
```

每一个调用select()系统调用的应用进程都会存在一个struct poll\_wqueues结构体，用来统一辅佐实现这个进程中所有待监测的fd的轮询工作，后面所有的工作和都这个结构体有关，所以它非常重要。
poll\_wqueues这个结构体的定义为：

```c
struct poll_wqueues {
    poll_table pt;
    //实际上结构体poll_wqueues内嵌的poll_table_entry数组inline_entries[]的大小是有限的，
    //如果空间不够用，后续会动态申请物理内存页以链表的形式挂载poll_wqueues.table上统一管理
    struct poll_table_page *table; 
    //保存当前调用select的用户进程struct task_struct结构体
    struct task_struct *polling_task;
    int triggered; //当前用户进程被唤醒后置成1，以免该进程接着进睡眠
    int error;
    int inline_index; //数组inline_entries的引用下标
    //每一个监控的fd会申请一个poll_table_entry，用于后面的__poll_wait
    struct poll_table_entry inline_entries[N_INLINE_POLL_ENTRIES];
};

typedef struct poll_table_struct {
    poll_queue_proc _qproc; //会在后面的f_op->的poll过程调用
    __poll_t _key;
} poll_table;

struct poll_table_page {
    struct poll_table_page * next;
    struct poll_table_entry * entry; //wait等待队列项
    struct poll_table_entry entries[0]; //wait的等待队列头
};

struct poll_table_entry {
    struct file *filp;//指向特定fd对应的file结构体;
    __poll_t key; //等待特定fd对应硬件设备的事件掩码，如POLLIN、 POLLOUT、POLLERR
    wait_queue_entry_t wait; //代表调用select()的应用进程，
    //等待在fd对应设备的特定事件 (读或者写)的等待队列头上的等待队列项
    wait_queue_head_t *wait_address;//设备驱动程序中特定事件的等待队列头
};
```

poll\_initwait()的定义为：

```c
void poll_initwait(struct poll_wqueues *pwq)
{
	//将结构体poll_wqueues->poll_table->poll_queue_proc赋值为__pollwait，
    //__pollwait会在后面的f_op->的poll过程调用
    init_poll_funcptr(&pwq->pt, __pollwait);
    pwq->polling_task = current;//将当前进程记录在pwq结构体
    pwq->triggered = 0;
    pwq->error = 0;
    pwq->table = NULL;
    pwq->inline_index = 0;
}
```

```c
    /////do_select（续）//////
    poll_initwait(&table);
    wait = &table.pt;
    if (end_time && !end_time->tv_sec && !end_time->tv_nsec) {
        wait->_qproc = NULL;
        timed_out = 1;  
    }

    if (end_time && !timed_out)
        slack = select_estimate_accuracy(end_time);

    retval = 0;
    //最外面是一个无限循环，它只有在poll到有效的事件，或者超时，或者有中断发生时，才会退出
    for (;;) {
        unsigned long *rinp, *routp, *rexp, *inp, *outp, *exp;
        bool can_busy_loop = false;
        //首先获取需要监控的三类fd_set
        inp = fds->in; outp = fds->out; exp = fds->ex;
        //初始化用于保存返回值的三类fd_set对应的unsigned long数组
        rinp = fds->res_in; routp = fds->res_out; rexp = fds->res_ex;
        //开始循环遍历覆盖的所有fd
        for (i = 0; i < n; ++rinp, ++routp, ++rexp) {
            unsigned long in, out, ex, all_bits, bit = 1, j;
            unsigned long res_in = 0, res_out = 0, res_ex = 0;
            __poll_t mask;

            in = *inp++; out = *outp++; ex = *exp++;
            all_bits = in | out | ex;
            //当前的3个long中的每一位均为0，不存在监控的fd，换下一个long
            if (all_bits == 0) {
                i += BITS_PER_LONG;
                continue;
            }
            //遍历一个long中的64个bit
            for (j = 0; j < BITS_PER_LONG; ++j, ++i, bit <<= 1) {
                struct fd f;
                if (i >= n)
                    break;
                //该bit无监控的fd
                if (!(bit & all_bits))
                    continue;
                f = fdget(i);
                if (f.file) {
                    //针对当前fd, 设置其需要监控的事件
                    //POLLEX_SET/POLLIN_SET/POLLOUT_SET
                    wait_key_set(wait, in, out, bit, busy_flag);
                    //初始化wait entry, 将其加入到这个fd对应的文件的等待队列中
                    //获取当前文件是否有读，写，异常等事件并返回
                    //poll函数返回的mask是设备的状态掩码
                    mask = vfs_poll(f.file, wait);
```

vfs\_poll定义在poll.h中：


```c
static inline __poll_t vfs_poll(struct file *file, struct poll_table_struct *pt)
{
    if (unlikely(!file->f_op->poll))
        return DEFAULT_POLLMASK;
    return file->f_op->poll(file, pt);
}
```

每一个文件系统都有自己的操作集合，不同的file poll操作可能会不同，但都会执行poll\_wait()，该方法真正执行的便是前面的回调函数\_\_pollwait，把自己挂入等待队列。
如fs/select.c注释所言：

```c
/* Two very simple procedures, poll_wait() and poll_freewait() make all the
 * work.  poll_wait() is an inline-function defined in <linux/poll.h>,
 * as all select/poll functions have to call it to add an entry to the
 * poll table.
 * /
```

```c
/* Add a new entry to poll_table*/
static void __pollwait(struct file *filp, wait_queue_head_t *wait_address, poll_table *p)
{
    //根据poll_wqueues的成员pt指针p找到所在的poll_wqueues结构指针
    struct poll_wqueues *pwq = container_of(p, struct poll_wqueues, pt);
    struct poll_table_entry *entry = poll_get_entry(pwq);
    if (!entry)
        return;
    //创建对应该file的poll_table_entry
    entry->filp = get_file(filp);
    entry->wait_address = wait_address;
    entry->key = p->_key;
    //设置entry->wait.func = pollwake
    init_waitqueue_func_entry(&entry->wait, pollwake);
    entry->wait.private = pwq;// 设置private内容为pwq
    //将该等待队列项添加到从驱动程序中传递过来的等待队列头中去
    add_wait_queue(wait_address, &entry->wait);
}
```

```c
/////do_select（续）//////
                    fdput(f);
                    //按位与，看是否有相关事件
                    if ((mask & POLLIN_SET) && (in & bit)) {
                        res_in |= bit;
                        retval++;
                        //所有的waiters已注册，因此不需要为下一轮循环提供poll_table->_qproc
                        wait->_qproc = NULL;
                    }
                    if ((mask & POLLOUT_SET) && (out & bit)) {
                        res_out |= bit;
                        retval++;
                        wait->_qproc = NULL;
                    }
                    if ((mask & POLLEX_SET) && (ex & bit)) {
                        res_ex |= bit;
                        retval++;
                        wait->_qproc = NULL;
                    }
                    /* got something, stop busy polling */
                    if (retval) {
                        can_busy_loop = false;
                        busy_flag = 0;

                    /*
                     * only remember a returned
                     * POLL_BUSY_LOOP if we asked for it
                     */
                    } else if (busy_flag & mask)
                        can_busy_loop = true;
                    }
            }
            // 按unsigned long赋值给返回值数组元素
            // 若该bit上的fd表示的文件有读操作且是fd_set in监控的文件，将res_in的该位置1
            if (res_in)
                *rinp = res_in;
            if (res_out)
                *routp = res_out;
            if (res_ex)
                *rexp = res_ex;
            //这里主动出让CPU, 进行一次调度
            cond_resched();
        }
        wait->_qproc = NULL;
        // 四种情况下会返回
        // 1. 任意监控的fd上有事件发生
        // 2. 超时
        // 3. 有中断发生
        if (retval || timed_out || signal_pending(current))
            break;
        // 4. wait queue相关操作发生错误
        if (table.error) {
            retval = table.error;
            break;
        }
        /* only if found POLL_BUSY_LOOP sockets && not out of time */
        if (can_busy_loop && !need_resched()) {
            if (!busy_start) {
                busy_start = busy_loop_current_time();
                continue;
            }
            if (!busy_loop_timeout(busy_start))
            continue;
        }
        busy_flag = 0;
        /*
         * If this is the first loop and we have a timeout
         * given, then we convert to ktime_t and set the to
         * pointer to the expiry value.
         */
        if (end_time && !to) {
            expire = timespec64_to_ktime(*end_time);
            to = &expire;
        }

        //当前监控的fd上没有事件发生，也没有超时或中断发生，
        //将当前进程设置为 TASK_INTERRUPTIBLE，并调用 schedule
        if (!poll_schedule_timeout(&table, TASK_INTERRUPTIBLE, to, slack))
        timed_out = 1;
    }
    //当进程唤醒后，将就绪事件结果保存在fds的res_in、res_out、res_ex，
    //将进程从所有的等待队列中移除
    poll_freewait(&table);

    return retval;
}

```

```c
//poll_freewait依旧是遍历实现的
void poll_freewait(struct poll_wqueues *pwq)
{
    struct poll_table_page * p = pwq->table;
    int i;
    for (i = 0; i < pwq->inline_index; i++)
        free_poll_entry(pwq->inline_entries + i);
    while (p) {
        struct poll_table_entry * entry;
        struct poll_table_page *old;
        entry = p->entry;
        do {
            entry--;
            free_poll_entry(entry);
        } while (entry > p->entries);
        old = p;
        p = p->next;
        free_page((unsigned long) old);
    }
}
```

### poll

和select()不一样的是，poll()没有使用三个基于位的文件描述符set，而是使用了链表，这样就避免了select只能监控1024个文件的问题。

poll的系统调用定义在```fs/select.c```中。

```c
SYSCALL_DEFINE3(poll, struct pollfd __user *, ufds, 
unsigned int, nfds, int, timeout_msecs)
{
	struct timespec64 end_time, *to = NULL;
	int ret;

//设置超时
	if (timeout_msecs >= 0) {
		to = &end_time;
		poll_select_set_timeout(to, timeout_msecs / MSEC_PER_SEC,
			NSEC_PER_MSEC * (timeout_msecs % MSEC_PER_SEC));
	}

//核心逻辑
	ret = do_sys_poll(ufds, nfds, to);

	if (ret == -ERESTARTNOHAND) {
		struct restart_block *restart_block;

		restart_block = &current->restart_block;
		restart_block->fn = do_restart_poll;
		restart_block->poll.ufds = ufds;
		restart_block->poll.nfds = nfds;

		if (timeout_msecs >= 0) {
			restart_block->poll.tv_sec = end_time.tv_sec;
			restart_block->poll.tv_nsec = end_time.tv_nsec;
			restart_block->poll.has_timeout = 1;
		} else
			restart_block->poll.has_timeout = 0;

		ret = -ERESTART_RESTARTBLOCK;
	}
	return ret;
}
```

pollfd表示监控的文件

```c
struct pollfd {
	int fd; //文件描述符
	short events; //监控的事件
	short revents;
};
```

```c
static int do_sys_poll(struct pollfd __user *ufds, unsigned int nfds,
		struct timespec64 *end_time)
{
	struct poll_wqueues table;
	int err = -EFAULT, fdcount, len;
	/* Allocate small arguments on the stack to save memory and be
	   faster - use long to make sure the buffer is aligned properly
	   on 64 bit archs to avoid unaligned access */
	long stack_pps[POLL_STACK_ALLOC/sizeof(long)];
    //这里和select的实现不同，poll是使用链表实现的，因此避免了只能监控有限个文件的问题
	struct poll_list *const head = (struct poll_list *)stack_pps;
 	struct poll_list *walk = head;
 	unsigned long todo = nfds;
```

poll\_list结构体的定义为：

```c
struct poll_list {
	struct poll_list *next;
	int len;
	struct pollfd entries[0];
};

```
这里有一个诡异的地方是entries字段是一个长度为0的数组，[它的作用与指针相同，但可以方便内存管理](https://www.cnblogs.com/felove2013/articles/4050226.html)。

```c
/////do_sys_poll（续）//////
	if (nfds > rlimit(RLIMIT_NOFILE))
		return -EINVAL;

	len = min_t(unsigned int, nfds, N_STACK_PPS);
	//将用户传入的pollfd数组拷贝到内核空间
	for (;;) {
		walk->next = NULL;
		walk->len = len;
		if (!len)
			break;
		if (copy_from_user(walk->entries, ufds + nfds-todo,
					sizeof(struct pollfd) * walk->len))
			goto out_fds;
		todo -= walk->len;
		if (!todo)
			break;
		len = min(todo, POLLFD_PER_PAGE);
		walk = walk->next = kmalloc(struct_size(walk, entries, len),
					    GFP_KERNEL);
		if (!walk) {
			err = -ENOMEM;
			goto out_fds;
		}
	}
	//和select相同
	poll_initwait(&table);
	//核心逻辑
	fdcount = do_poll(head, &table, end_time);
	//和select相同
	poll_freewait(&table);
	//将revents值拷贝到用户空间ufds
	for (walk = head; walk; walk = walk->next) {
		struct pollfd *fds = walk->entries;
		int j;
		for (j = 0; j < walk->len; j++, ufds++)
			if (__put_user(fds[j].revents, &ufds->revents))
				goto out_fds;
  	}
	err = fdcount;
out_fds:
	walk = head->next;
	while (walk) {
		struct poll_list *pos = walk;
		walk = walk->next;
		kfree(pos);
	}
	return err;
}
```

poll的核心逻辑在do\_poll中，


```c
static int do_poll(
    struct poll_list *list, //监控的文件列表
    struct poll_wqueues *wait, //统一辅佐该进程进行轮训监控fd的工作
	struct timespec64 *end_time //超时
    )
{
	poll_table* pt = &wait->pt;
	ktime_t expire, *to = NULL;
	int timed_out = 0, count = 0;
	u64 slack = 0;
	__poll_t busy_flag = net_busy_loop_on() ? POLL_BUSY_LOOP : 0;
	unsigned long busy_start = 0;

	/* Optimise the no-wait case */
	if (end_time && !end_time->tv_sec && !end_time->tv_nsec) {
		pt->_qproc = NULL;
		timed_out = 1;
	}

	if (end_time && !timed_out)
		slack = select_estimate_accuracy(end_time);

    //和select一样的无限循环，只是遍历链表poll_list表示的文件
	for (;;) {
		struct poll_list *walk;
		bool can_busy_loop = false;

        //遍历所有的文件
		for (walk = list; walk != NULL; walk = walk->next) {
			struct pollfd * pfd, * pfd_end;
            //walk->entries是我们之前提到的长度为0的数组，它在此处的作用与指针相同
			pfd = walk->entries;
			pfd_end = pfd + walk->len;
            //这里就是遍历poll_list每一个元素的entries，也就是pollfd数组
			for (; pfd != pfd_end; pfd++) {
                //此后的逻辑和select十分相像，这里抽象除了一个do_pollfd的函数，用于：
				/*
				 * Fish for events. If we found one, record it
				 * and kill poll_table->_qproc, so we don't
				 * needlessly register any other waiters after
				 * this. They'll get immediately deregistered
				 * when we break out and return.
				 */
				if (do_pollfd(pfd, pt, &can_busy_loop,
					      busy_flag)) {
					count++;
					pt->_qproc = NULL;
					/* found something, stop busy polling */
					busy_flag = 0;
					can_busy_loop = false;
				}
			}
		}
		/*
		 * All waiters have already been registered, so don't provide
		 * a poll_table->_qproc to them on the next loop iteration.
		 */
		pt->_qproc = NULL;
		if (!count) {
			count = wait->error;
			if (signal_pending(current))//有待处理信号，则跳出循环
				count = -ERESTARTNOHAND;
		}
		if (count || timed_out)//监控事件触发，或者超时则跳出循环
			break;

		/* only if found POLL_BUSY_LOOP sockets && not out of time */
		if (can_busy_loop && !need_resched()) {
			if (!busy_start) {
				busy_start = busy_loop_current_time();
				continue;
			}
			if (!busy_loop_timeout(busy_start))
				continue;
		}
		busy_flag = 0;

		/*
		 * If this is the first loop and we have a timeout
		 * given, then we convert to ktime_t and set the to
		 * pointer to the expiry value.
		 */
		if (end_time && !to) {
			expire = timespec64_to_ktime(*end_time);
			to = &expire;
		}
		//设置进程状态
		if (!poll_schedule_timeout(wait, TASK_INTERRUPTIBLE, to, slack))
			timed_out = 1;
	}
	return count;
}
```

```c
static inline __poll_t do_pollfd(struct pollfd *pollfd, poll_table *pwait,
				     bool *can_busy_poll,
				     __poll_t busy_flag)
{
	int fd = pollfd->fd;
	__poll_t mask = 0, filter;
	struct fd f;

	if (fd < 0)
		goto out;
	mask = EPOLLNVAL;
	f = fdget(fd);
	if (!f.file)
		goto out;

	/* userland u16 ->events contains POLL... bitmap */
	filter = demangle_poll(pollfd->events) | EPOLLERR | EPOLLHUP;
	pwait->_key = filter | busy_flag;
    //核心函数调用(*f_op->poll)(f.file, wait)，
    //就是等于调用文件系统的poll方法，
    //不同驱动设备实现方法略有不同，但都会执行poll_wait()，
    //该方法真正执行的便是前面的回调函数__pollwait，把自己挂入等待队列。
	mask = vfs_poll(f.file, pwait);
	if (mask & busy_flag)
		*can_busy_poll = true;
	mask &= filter;		/* Mask out unneeded events. */
	fdput(f);

out:
	/* ... and so does ->revents */
	pollfd->revents = mangle_poll(mask);
	return mask;
}

```

### epoll

select缺点

* 每次调用select都需要将进程加入到所有监视文件的等待队列，每次唤醒都需要从每个队列中移除。这里涉及了两次遍历，而且每次都要将整个fds列表传递给内核，有一定的开销。正是因为遍历操作开销大，出于效率的考量，才会规定select的最大监视数量，默认只能监视1024个文件描述符。

poll缺点

* 从上面看select和poll都需要在返回后，通过遍历文件描述符来获取已经就绪的文件。同时连接的大量文件在同一时刻可能只有很少的处于就绪状态，因此随着监视的描述符数量的增长，其性能会线性下降。

epoll优势

* 监视的描述符数量不受限制，所支持的FD上限是最大可以打开文件的数目，具体数目可以cat /proc/sys/fs/file-max查看
* IO性能不会随着监视fd的数量增长而下降。epoll不同于select和poll轮询的方式，而是通过每个fd定义的回调函数来实现的，只有就绪的fd才会执行回调函数。

（如果没有大量的空闲或者死亡连接，epoll的效率并不会比select/poll高很多。但当遇到大量的空闲连接的场景下，epoll的效率大大高于select/poll。）

epoll的系统调用定义在```fs/eventpoll.c```中。

相比select和poll都只有一个方法，epoll有三个系统调用：

```c
int epoll_create(int size)；
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)；
int epoll_wait(int epfd, struct epoll_event * events, int maxevents, int timeout);
```

#### 相关数据结构

```c
//eventpoll也是文件系统的一员，因此也有等待队列
struct eventpoll {
	struct mutex mtx;//保证在epoll使用文件时，文件不会被删除
	//等待队列，epoll_wait时如果当前没有拿到有效的事件，
	//将当前task加入这个等待队列后作进程切换，等待被唤醒
	wait_queue_head_t wq;
	/* Wait queue used by file->poll() */
  	// eventpoll对象在使用时都会对应一个struct file对象，赋值到其private_data，
 	// 其本身也可以被 poll，那也就需要一个wait queue
	wait_queue_head_t poll_wait;
	struct list_head rdllist;//所有有事件触发的文件描述符列表
	rwlock_t lock;//rdllist&ovflist的锁
	struct rb_root_cached rbr;//用于储存已监控fd的红黑树根节点
	//当正在向用户空间传递事件，则rdllist会被加锁
	//则就绪事件会临时放到该队列，否则直接放到rdllist
	struct epitem *ovflist;
	struct wakeup_source *ws;//当ep_scan_ready_list运行时使用wakeup_source
	struct user_struct *user;//创建eventpoll描述符的用户
	struct file *file;//指向当前这个eventpoll结构
	int visited;
	struct list_head visited_list_link;
};

struct epitem {
	union {
		struct rb_node rbn;//RB树节点将此结构链接到eventpoll RB树
		struct rcu_head rcu;//用于释放结构体epitem
	};
	struct list_head rdllink;//用于将此结构链接到eventpoll就绪列表的列表标头
	struct epitem *next;//配合ovflist一起使用来保持单向链的条目
	struct epoll_filefd ffd;//此条目引用的文件描述符信息
	int nwait;//附加到poll轮询中的活跃等待队列数
	struct list_head pwqlist;//保存等待队列的链表
	struct eventpoll *ep;//epi所属的ep
	struct list_head fllink;//链接到file条目列表的列表头
	struct wakeup_source __rcu *ws;//设置EPOLLWAKEUP时使用的wakeup_source
	struct epoll_event event;//监控的事件
};

struct epoll_event {
    /*
     * 其中events表示感兴趣的事件和被触发的事件，可能的取值为：
     * EPOLLIN：表示对应的文件描述符可以读；
     * EPOLLOUT：表示对应的文件描述符可以写；
     * EPOLLPRI：表示对应的文件描述符有紧急的数可读；
     * EPOLLERR：表示对应的文件描述符发生错误；
     * EPOLLHUP：表示对应的文件描述符被挂断；
     * EPOLLET：ET的epoll工作模式；
     */
	__poll_t events;
	__u64 data;
} EPOLL_PACKED;

struct epoll_filefd {
	struct file *file;
	int fd;
} __packed;

```

#### epoll_create

```c
//创建并初始化eventpoll结构体ep，并将ep放入file->private，并返回fd
SYSCALL_DEFINE1(epoll_create, int, size)
{
	if (size <= 0)
		return -EINVAL;
    //size仅仅用来检测是否大于0，并没有真正使用
	return do_epoll_create(0);
}
```

```c
/*
 * Open an eventpoll file descriptor.
 */
static int do_epoll_create(int flags)
{
	int error, fd;
	struct eventpoll *ep = NULL;
	struct file *file;
	BUILD_BUG_ON(EPOLL_CLOEXEC != O_CLOEXEC);
	//校验传入参数flags, 目前仅支持 EPOLL_CLOEXEC 一种，如果是其他的，立即返回失败
	if (flags & ~EPOLL_CLOEXEC)
		return -EINVAL;
	/*
	 * 创建内部数据结构eventpoll
	 */
	error = ep_alloc(&ep);
```

```c
static int ep_alloc(struct eventpoll **pep)
{
	int error;
	struct user_struct *user;
	struct eventpoll *ep;

	user = get_current_user();
	error = -ENOMEM;
	ep = kzalloc(sizeof(*ep), GFP_KERNEL);
	if (unlikely(!ep))
		goto free_uid;

	mutex_init(&ep->mtx);
	rwlock_init(&ep->lock);
	init_waitqueue_head(&ep->wq);//初始化epoll文件的等待队列
	init_waitqueue_head(&ep->poll_wait);
	INIT_LIST_HEAD(&ep->rdllist);
	ep->rbr = RB_ROOT_CACHED;
	ep->ovflist = EP_UNACTIVE_PTR;
	ep->user = user;
	*pep = ep;
	return 0;
free_uid:
	free_uid(user);
	return error;
}
```

```c
/////do_epoll_create（续）/////
	if (error < 0)
		return error;
	/*
	 * Creates all the items needed to setup an eventpoll file. That is,
	 * a file structure and a free file descriptor.
     * 查询未使用的fd
	 */
	fd = get_unused_fd_flags(O_RDWR | (flags & O_CLOEXEC));
	if (fd < 0) {
		error = fd;
		goto out_free_ep;
	}

    //创建eventpoll的file实例
	file = anon_inode_getfile("[eventpoll]", &eventpoll_fops, ep,
				 O_RDWR | (flags & O_CLOEXEC));
	if (IS_ERR(file)) {
		error = PTR_ERR(file);
		goto out_free_fd;
	}
	ep->file = file;
    //建立fd和file的关联关系
	fd_install(fd, file);
	return fd;

out_free_fd:
	put_unused_fd(fd);
out_free_ep:
	ep_free(ep);
	return error;
}

```

#### epoll_ctl

```c
/*
 * The following function implements the controller interface for
 * the eventpoll file that enables the insertion/removal/change of
 * file descriptors inside the interest set.
 */
 //将一个fd添加到一个eventpoll中，或从中删除，或如果此fd已经在eventpoll中，可以更改其监控事件
SYSCALL_DEFINE4(epoll_ctl, int, epfd, int, op, int, fd,
		struct epoll_event __user *, event)
{
	int error;
	int full_check = 0;
	struct fd f, tf;
	struct eventpoll *ep;
	struct epitem *epi;
	struct epoll_event epds;
	struct eventpoll *tep = NULL;

	error = -EFAULT;
   //将不是EPOLL_CTL_DEL操作的用户空间的epoll_event 拷贝到内核
	if (ep_op_has_event(op) &&
	    copy_from_user(&epds, event, sizeof(struct epoll_event)))
		goto error_return;

	error = -EBADF;
    //epfd对应的文件
	f = fdget(epfd);
	if (!f.file)
		goto error_return;

	/* Get the "struct file *" for the target file */
    //fd对应的文件
	tf = fdget(fd);
	if (!tf.file)
		goto error_fput;

	/* The target file descriptor must support poll */
	error = -EPERM;
	if (!file_can_poll(tf.file))
		goto error_tgt_fput;

	/* Check if EPOLLWAKEUP is allowed */
	if (ep_op_has_event(op))
		ep_take_care_of_epollwakeup(&epds);

	/*
	 * We have to check that the file structure underneath the file descriptor
	 * the user passed to us _is_ an eventpoll file. And also we do not permit
	 * adding an epoll file descriptor inside itself.
	 */
	error = -EINVAL;
	// epoll不能自己监控自己
	if (f.file == tf.file || !is_file_epoll(f.file))
		goto error_tgt_fput;

	/*
	 * epoll adds to the wakeup queue at EPOLL_CTL_ADD time only,
	 * so EPOLLEXCLUSIVE is not allowed for a EPOLL_CTL_MOD operation.
	 * Also, we do not currently supported nested exclusive wakeups.
	 */
	if (ep_op_has_event(op) && (epds.events & EPOLLEXCLUSIVE)) {
		if (op == EPOLL_CTL_MOD)
			goto error_tgt_fput;
		if (op == EPOLL_CTL_ADD && (is_file_epoll(tf.file) ||
				(epds.events & ~EPOLLEXCLUSIVE_OK_BITS)))
			goto error_tgt_fput;
	}

	/*
	 * At this point it is safe to assume that the "private_data" contains
	 * our own data structure.
     * 取出epoll_create过程创建的ep
	 */
	ep = f.file->private_data;

	/*
	 * When we insert an epoll file descriptor, inside another epoll file
	 * descriptor, there is the change of creating closed loops, which are
	 * better be handled here, than in more critical paths. While we are
	 * checking for loops we also determine the list of files reachable
	 * and hang them on the tfile_check_list, so we can check that we
	 * haven't created too many possible wakeup paths.
	 *
	 * We do not need to take the global 'epumutex' on EPOLL_CTL_ADD when
	 * the epoll file descriptor is attaching directly to a wakeup source,
	 * unless the epoll file descriptor is nested. The purpose of taking the
	 * 'epmutex' on add is to prevent complex toplogies such as loops and
	 * deep wakeup paths from forming in parallel through multiple
	 * EPOLL_CTL_ADD operations.
	 *
	 * 这里要处理插入时循环嵌套的情况
	 */
	mutex_lock_nested(&ep->mtx, 0);
	if (op == EPOLL_CTL_ADD) {
		if (!list_empty(&f.file->f_ep_links) ||
						is_file_epoll(tf.file)) {
			full_check = 1;
			mutex_unlock(&ep->mtx);
			mutex_lock(&epmutex);
			if (is_file_epoll(tf.file)) {
				error = -ELOOP;
				if (ep_loop_check(ep, tf.file) != 0) {
					clear_tfile_check_list();
					goto error_tgt_fput;
				}
			} else
				list_add(&tf.file->f_tfile_llink,
							&tfile_check_list);
			mutex_lock_nested(&ep->mtx, 0);
			if (is_file_epoll(tf.file)) {
				tep = tf.file->private_data;
				mutex_lock_nested(&tep->mtx, 1);
			}
		}
	}

	/*
	 * Try to lookup the file inside our RB tree, Since we grabbed "mtx"
	 * above, we can be sure to be able to use the item looked up by
	 * ep_find() till we release the mutex.
	 * 
	 * 查看对应的epitem是否已经在红黑树上存在，即是否已经添加过
  	 */
	epi = ep_find(ep, tf.file, fd);

	error = -EINVAL;
	switch (op) {
	case EPOLL_CTL_ADD:
		if (!epi) {
			epds.events |= EPOLLERR | EPOLLHUP;
			// 将当前fd加入红黑树
			error = ep_insert(ep, &epds, tf.file, fd, full_check);
```

```c
//将待监听的fd加入到epoll中去
static int ep_insert(struct eventpoll *ep, const struct epoll_event *event, 
struct file *tfile, int fd, int full_check)
{
	int error, pwake = 0;
	__poll_t revents;
	long user_watches;
	struct epitem *epi;
	struct ep_pqueue epq;

	lockdep_assert_irqs_enabled();
	//作max_user_watches检验
	//内核对系统中所有使用epoll监听fd所消耗的内存作了限制，
	//且这个限制是针对当前linux user id的。
	//默认情况下每个用户下epoll为注册文件描述符可用的内存是内核可使用内存的1/25
	user_watches = atomic_long_read(&ep->user->epoll_watches);
	if (unlikely(user_watches >= max_user_watches))
		return -ENOSPC;
	//初始化epitem
	if (!(epi = kmem_cache_alloc(epi_cache, GFP_KERNEL)))
		return -ENOMEM;
	/* Item initialization follow here ... */
	INIT_LIST_HEAD(&epi->rdllink);
	INIT_LIST_HEAD(&epi->fllink);
	INIT_LIST_HEAD(&epi->pwqlist);
	epi->ep = ep;
	ep_set_ffd(&epi->ffd, tfile, fd);
	epi->event = *event;
	epi->nwait = 0;
	epi->next = EP_UNACTIVE_PTR;
	if (epi->event.events & EPOLLWAKEUP) {
		error = ep_create_wakeup_source(epi);
		if (error)
			goto error_create_wakeup_source;
	} else {
		RCU_INIT_POINTER(epi->ws, NULL);
	}

	/* Initialize the poll table using the queue callback */
	epq.epi = epi;
	//设置轮询回调函数
	init_poll_funcptr(&epq.pt, ep_ptable_queue_proc);

	/*
	 * Attach the item to the poll hooks and get current event bits.
	 * We can safely use the file* here because its usage count has
	 * been increased by the caller of this function. Note that after
	 * this operation completes, the poll callback can start hitting
	 * the new item.
	 */
	//执行poll方法
	revents = ep_item_poll(epi, &epq.pt, 1);
```

```c
/*
 * Differs from ep_eventpoll_poll() in that internal callers already have
 * the ep->mtx so we need to start from depth=1, such that mutex_lock_nested()
 * is correctly annotated.
 */
static __poll_t ep_item_poll(const struct epitem *epi, poll_table *pt,
				 int depth)
{
	struct eventpoll *ep;
	bool locked;

	pt->_key = epi->event.events;
	if (!is_file_epoll(epi->ffd.file))
	//vfs_poll出现！它会调用文件系统的poll核心方法epi->ffd.file->f_op->poll，
	//poll会执行poll_wait()，
	//poll_wait()会调用epq.pt.qproc所对应的回调函数ep_ptable_queue_proc
		return vfs_poll(epi->ffd.file, pt) & epi->event.events;

	ep = epi->ffd.file->private_data;
	poll_wait(epi->ffd.file, &ep->poll_wait, pt);
	locked = pt && (pt->_qproc == ep_ptable_queue_proc);

	return ep_scan_ready_list(epi->ffd.file->private_data,
				  ep_read_events_proc, &depth, depth,
				  locked) & epi->event.events;
}
```

```c
/*
 * This is the callback that is used to add our wait queue to the
 * target file wakeup lists.
 * 设置pwq->wait的成员变量func唤醒回调函数为ep_poll_callback，
 * 并将ep_poll_callback放入等待队列whead
 */
static void ep_ptable_queue_proc(struct file *file, wait_queue_head_t *whead,
				 poll_table *pt)
{
	struct epitem *epi = ep_item_from_epqueue(pt);
	struct eppoll_entry *pwq;

	if (epi->nwait >= 0 && (pwq = kmem_cache_alloc(pwq_cache, GFP_KERNEL))) {
		//初始化回调方法
		init_waitqueue_func_entry(&pwq->wait, ep_poll_callback);
		pwq->whead = whead;
		pwq->base = epi;
		if (epi->event.events & EPOLLEXCLUSIVE)
			//将ep_poll_callback放入等待队列whead
			add_wait_queue_exclusive(whead, &pwq->wait);
		else
			add_wait_queue(whead, &pwq->wait);
		//将llink 放入epi->pwqlist的尾部
		list_add_tail(&pwq->llink, &epi->pwqlist);
		epi->nwait++;
	} else {
		/* We have to signal that an error occurred */
		epi->nwait = -1;
	}
}
```

```c
//ep_poll_callback函数核心功能是将被目标fd的就绪事件到来时，
//将fd对应的epitem实例添加到就绪队列。
//当应用调用epoll_wait()时，
//内核会将就绪队列中的事件报告给应用。
static int ep_poll_callback(wait_queue_entry_t *wait, unsigned mode, int sync, void *key)
{
	int pwake = 0;
	struct epitem *epi = ep_item_from_wait(wait);
	struct eventpoll *ep = epi->ep;
	__poll_t pollflags = key_to_poll(key);
	unsigned long flags;
	int ewake = 0;

	read_lock_irqsave(&ep->lock, flags);

	ep_set_busy_poll_napi_id(epi);

	/*
	 * If the event mask does not contain any poll(2) event, we consider the
	 * descriptor to be disabled. This condition is likely the effect of the
	 * EPOLLONESHOT bit that disables the descriptor when an event is received,
	 * until the next EPOLL_CTL_MOD will be issued.
	 */
	if (!(epi->event.events & ~EP_PRIVATE_BITS))
		goto out_unlock;

	/*
	 * Check the events coming with the callback. At this stage, not
	 * every device reports the events in the "key" parameter of the
	 * callback. We need to be able to handle both cases here, hence the
	 * test for "key" != NULL before the event match test.
	 */
	if (pollflags && !(pollflags & epi->event.events))
		goto out_unlock;

	/*
	 * If we are transferring events to userspace, we can hold no locks
	 * (because we're accessing user memory, and because of linux f_op->poll()
	 * semantics). All the events that happen during that period of time are
	 * chained in ep->ovflist and requeued later on.
	 */
	if (READ_ONCE(ep->ovflist) != EP_UNACTIVE_PTR) {
		if (epi->next == EP_UNACTIVE_PTR &&
		    chain_epi_lockless(epi))
			ep_pm_stay_awake_rcu(epi);
		goto out_unlock;
	}

	/* If this file is already in the ready list we exit soon */
	if (!ep_is_linked(epi) &&
	    list_add_tail_lockless(&epi->rdllink, &ep->rdllist)) {
		ep_pm_stay_awake_rcu(epi);
	}

	/*
	 * Wake up ( if active ) both the eventpoll wait list and the ->poll()
	 * wait list.
	 */
	if (waitqueue_active(&ep->wq)) {
		if ((epi->event.events & EPOLLEXCLUSIVE) &&
					!(pollflags & POLLFREE)) {
			switch (pollflags & EPOLLINOUT_BITS) {
			case EPOLLIN:
				if (epi->event.events & EPOLLIN)
					ewake = 1;
				break;
			case EPOLLOUT:
				if (epi->event.events & EPOLLOUT)
					ewake = 1;
				break;
			case 0:
				ewake = 1;
				break;
			}
		}
		wake_up(&ep->wq);
	}
	if (waitqueue_active(&ep->poll_wait))
		pwake++;

out_unlock:
	read_unlock_irqrestore(&ep->lock, flags);

	/* We have to call this outside the lock */
	if (pwake)
		ep_poll_safewake(&ep->poll_wait);

	if (!(epi->event.events & EPOLLEXCLUSIVE))
		ewake = 1;

	if (pollflags & POLLFREE) {
		/*
		 * If we race with ep_remove_wait_queue() it can miss
		 * ->whead = NULL and do another remove_wait_queue() after
		 * us, so we can't use __remove_wait_queue().
		 */
		list_del_init(&wait->entry);
		/*
		 * ->whead != NULL protects us from the race with ep_free()
		 * or ep_remove(), ep_remove_wait_queue() takes whead->lock
		 * held by the caller. Once we nullify it, nothing protects
		 * ep/epi or even wait.
		 */
		smp_store_release(&ep_pwq_from_wait(wait)->whead, NULL);
	}

	return ewake;
}
```

```c
//////ep_insert(续)////////
	/*
	 * We have to check if something went wrong during the poll wait queue
	 * install process. Namely an allocation for a wait queue failed due
	 * high memory pressure.
	 */
	error = -ENOMEM;
	if (epi->nwait < 0)
		goto error_unregister;

	/* Add the current item to the list of active epoll hook for this file */
	spin_lock(&tfile->f_lock);
	list_add_tail_rcu(&epi->fllink, &tfile->f_ep_links);
	spin_unlock(&tfile->f_lock);

	/*
	 * Add the current item to the RB tree. All RB tree operations are
	 * protected by "mtx", and ep_insert() is called with "mtx" held.
	 * 将当前epi添加到RB树
	 */
	ep_rbtree_insert(ep, epi);

	/* now check if we've created too many backpaths */
	error = -EINVAL;
	if (full_check && reverse_path_check())
		goto error_remove_epi;

	/* We have to drop the new item inside our item list to keep track of it */
	write_lock_irq(&ep->lock);

	/* record NAPI ID of new item if present */
	ep_set_busy_poll_napi_id(epi);

	/* If the file is already "ready" we drop it inside the ready list */
	//事件就绪 并且 epi的就绪队列有数据，
	//我们将epi添加到就绪队列
	if (revents && !ep_is_linked(epi)) {
		list_add_tail(&epi->rdllink, &ep->rdllist);
		ep_pm_stay_awake(epi);

		/* Notify waiting tasks that events are available */
		//唤醒正在等待文件就绪，即调用epoll_wait的进程
		if (waitqueue_active(&ep->wq))
			wake_up(&ep->wq);
		if (waitqueue_active(&ep->poll_wait))
			pwake++;
	}

	write_unlock_irq(&ep->lock);

	atomic_long_inc(&ep->user->epoll_watches);

	/* We have to call this outside the lock */
	if (pwake)
		//唤醒等待eventpoll文件就绪的进程
		ep_poll_safewake(&ep->poll_wait);

	return 0;

error_remove_epi:
	spin_lock(&tfile->f_lock);
	list_del_rcu(&epi->fllink);
	spin_unlock(&tfile->f_lock);

	rb_erase_cached(&epi->rbn, &ep->rbr);

error_unregister:
	ep_unregister_pollwait(ep, epi);

	/*
	 * We need to do this because an event could have been arrived on some
	 * allocated wait queue. Note that we don't care about the ep->ovflist
	 * list, since that is used/cleaned only inside a section bound by "mtx".
	 * And ep_insert() is called with "mtx" held.
	 */
	write_lock_irq(&ep->lock);
	if (ep_is_linked(epi))
		list_del_init(&epi->rdllink);
	write_unlock_irq(&ep->lock);

	wakeup_source_unregister(ep_wakeup_source(epi));

error_create_wakeup_source:
	kmem_cache_free(epi_cache, epi);

	return error;
}
```

```c
//////epoll_ctl(续)///////
		} else
			error = -EEXIST;
		if (full_check)
			clear_tfile_check_list();
		break;
	case EPOLL_CTL_DEL:
		if (epi)
			error = ep_remove(ep, epi);
		else
			error = -ENOENT;
		break;
	case EPOLL_CTL_MOD:
		if (epi) {
			if (!(epi->event.events & EPOLLEXCLUSIVE)) {
				epds.events |= EPOLLERR | EPOLLHUP;
				error = ep_modify(ep, epi, &epds);
			}
		} else
			error = -ENOENT;
		break;
	}
	if (tep != NULL)
		mutex_unlock(&tep->mtx);
	mutex_unlock(&ep->mtx);

error_tgt_fput:
	if (full_check)
		mutex_unlock(&epmutex);

	fdput(tf);
error_fput:
	fdput(f);
error_return:

	return error;
}
```

#### epoll_wait

主要工作是执行ep_poll()方法

```c
SYSCALL_DEFINE4(epoll_wait, int, epfd, struct epoll_event __user *, events,
int, maxevents, int, timeout)
{
	return do_epoll_wait(epfd, events, maxevents, timeout);
}

/*
 * Implement the event wait interface for the eventpoll file. It is the kernel
 * part of the user space epoll_wait(2).
 */
static int do_epoll_wait(int epfd, struct epoll_event __user *events,
			 int maxevents, int timeout)
{
	int error;
	struct fd f;
	struct eventpoll *ep;
	//检测参数
	/* The maximum number of event must be greater than zero */
	if (maxevents <= 0 || maxevents > EP_MAX_EVENTS)
		return -EINVAL;
	//检查用户空间传递的内存是否可写
	/* Verify that the area passed by the user is writeable */
	if (!access_ok(events, maxevents * sizeof(struct epoll_event)))
		return -EFAULT;
	//获取eventpoll文件
	/* Get the "struct file *" for the eventpoll file */
	f = fdget(epfd);
	if (!f.file)
		return -EBADF;

	/*
	 * We have to check that the file structure underneath the fd
	 * the user passed to us _is_ an eventpoll file.
	 */
	error = -EINVAL;
	if (!is_file_epoll(f.file))
		goto error_fput;

	/*
	 * At this point it is safe to assume that the "private_data" contains
	 * our own data structure.
	 */
	ep = f.file->private_data;

	/* Time to fish for events ... */
	//核心：ep_poll()
	error = ep_poll(ep, events, maxevents, timeout);

error_fput:
	fdput(f);
	return error;
}
```

```c

/**
 * ep_poll - Retrieves ready events, and delivers them to the caller supplied
 *           event buffer.
 *
 * @ep: Pointer to the eventpoll context.
 * @events: Pointer to the userspace buffer where the ready events should be
 *          stored.
 * @maxevents: Size (in terms of number of events) of the caller event buffer.
 * @timeout: Maximum timeout for the ready events fetch operation, in
 *           milliseconds. If the @timeout is zero, the function will not block,
 *           while if the @timeout is less than zero, the function will block
 *           until at least one event has been retrieved (or an error
 *           occurred).
 *
 * Returns: Returns the number of ready events which have been fetched, or an
 *          error code, in case of error.
 */
static int ep_poll(struct eventpoll *ep, struct epoll_event __user *events,
		   int maxevents, long timeout)
{
	int res = 0, eavail, timed_out = 0;
	u64 slack = 0;
	bool waiter = false;
	wait_queue_entry_t wait;
	ktime_t expires, *to = NULL;

	lockdep_assert_irqs_enabled();

	if (timeout > 0) {
		struct timespec64 end_time = ep_set_mstimeout(timeout);

		slack = select_estimate_accuracy(&end_time);
		to = &expires;
		*to = timespec64_to_ktime(end_time);
	} else if (timeout == 0) {
		/*
		 * Avoid the unnecessary trip to the wait queue loop, if the
		 * caller specified a non blocking operation. We still need
		 * lock because we could race and not see an epi being added
		 * to the ready list while in irq callback. Thus incorrectly
		 * returning 0 back to userspace.
		 * timeout等于0为非阻塞操作，此处避免不必要的等待队列循环
		 */
		timed_out = 1;

		write_lock_irq(&ep->lock);
		eavail = ep_events_available(ep);
		write_unlock_irq(&ep->lock);

		goto send_events;
	}

fetch_events:

	if (!ep_events_available(ep))
		ep_busy_loop(ep, timed_out);

	eavail = ep_events_available(ep);
	if (eavail)
		goto send_events;

	/*
	 * Busy poll timed out.  Drop NAPI ID for now, we can add
	 * it back in when we have moved a socket with a valid NAPI
	 * ID onto the ready list.
	 */
	ep_reset_busy_poll_napi_id(ep);

	/*
	 * We don't have any available event to return to the caller.  We need
	 * to sleep here, and we will be woken by ep_poll_callback() when events
	 * become available.
	 */
	if (!waiter) {
		waiter = true;
		//将当前进程放入wait等待队列 
		init_waitqueue_entry(&wait, current);

		spin_lock_irq(&ep->wq.lock);
		//将当前进程加入eventpoll等待队列，等待文件就绪、超时或中断信号
		__add_wait_queue_exclusive(&ep->wq, &wait);
		spin_unlock_irq(&ep->wq.lock);
	}

	for (;;) {
		/*
		 * We don't want to sleep if the ep_poll_callback() sends us
		 * a wakeup in between. That's why we set the task state
		 * to TASK_INTERRUPTIBLE before doing the checks.
		 */
		set_current_state(TASK_INTERRUPTIBLE);
		/*
		 * Always short-circuit for fatal signals to allow
		 * threads to make a timely exit without the chance of
		 * finding more events available and fetching
		 * repeatedly.
		 */
		if (fatal_signal_pending(current)) {
		//有待处理信号，则跳出循环
			res = -EINTR;
			break;
		}

		eavail = ep_events_available(ep);
		if (eavail)
		//就绪队列不为空 或者超时，则跳出循环
			break;
		if (signal_pending(current)) {
		//有待处理信号，则跳出循环
			res = -EINTR;
			break;
		}

		if (!schedule_hrtimeout_range(to, slack, HRTIMER_MODE_ABS)) {
			timed_out = 1;
			break;
		}
	}

	__set_current_state(TASK_RUNNING);

send_events:
	/*
	 * Try to transfer events to user space. In case we get 0 events and
	 * there's still timeout left over, we go trying again in search of
	 * more luck.
	 * 尝试传输就绪事件到用户空间，如果没有获取就绪事件，但还剩下超时，则会再次retry
	 */
	if (!res && eavail &&
	    !(res = ep_send_events(ep, events, maxevents)) && !timed_out)
		goto fetch_events;

	if (waiter) {
		spin_lock_irq(&ep->wq.lock);
		__remove_wait_queue(&ep->wq, &wait);
		spin_unlock_irq(&ep->wq.lock);
	}

	return res;
}
```

## 参考
- 《深入理解Linux内核》
- 《Linux内核源代码情景分析》
- https://zhuanlan.zhihu.com/p/141447239
- https://www.linuxprobe.com/linux-io-multiplexing.html
- https://zhuanlan.zhihu.com/p/91428595
- http://gityuan.com/2019/01/05/linux-poll-select/
- http://gityuan.com/2019/01/06/linux-epoll/
- https://www.cnblogs.com/alyssaCui/archive/2013/04/01/2993886.html
- https://zhuanlan.zhihu.com/p/63179839
- https://juejin.im/entry/592e912f2f301e006c7c5842



