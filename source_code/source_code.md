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
SYSCALL_DEFINE5(select, int, n, fd_set __user *, inp, fd_set __user *, outp,
                fd_set __user *, exp, struct __kernel_old_timeval __user *, tvp)
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
我们可以看到FD_SET是设置fd_set中的某一位，每一位用来表示一个 fd, 这也就是 select针对读，定或异常每一类最多只能有 1024个fd 限制的由来。

```c
static int kern_select(
    int n, //这个n是三类不同的fd_set中所包括的fd数值的最大值+1, linux task打开句柄从0开始，不加1的话可能会少监控fd
    fd_set __user *inp, //当前进程在睡眠中等待来自哪一些已打开文件的输入
    fd_set __user *outp, //等待哪些文件的写操作
    fd_set __user *exp, //监视哪些通道发生了异常
    struct __kernel_old_timeval __user *tvp //睡眠等待的最长时间，指针为0表示无限期的睡眠等待
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
                if (poll_select_set_timeout(to, //timeout的指针
                                tv.tv_sec + (tv.tv_usec / USEC_PER_SEC), //秒
                                (tv.tv_usec % USEC_PER_SEC) * NSEC_PER_USEC) //纳秒
                                )
                        return -EINVAL;
        }
        //核心的功能在core_sys_select中实现
        ret = core_sys_select(n, inp, outp, exp, to);
        return poll_select_finish(
                    &end_time, 
                    tvp, 
                    PT_TIMEVAL, 
                    ret);
}
```

可以看到主要的逻辑在```core_sys_select```中，它与系统调用的参数仅有to不同，它本质上是tvp在内核中的拷贝。

fd_set_bits包含了in,out,ex的参数和结果，共6个bitmaps。
```c
typedef struct {
	unsigned long *in, *out, *ex;
	unsigned long *res_in, *res_out, *res_ex;
} fd_set_bits;
```

```c
int core_sys_select(int n, fd_set __user *inp, fd_set __user *outp,
			   fd_set __user *exp, struct timespec64 *end_time)
{
	fd_set_bits fds;
	void *bits;
	int ret, max_fds;
	size_t size, alloc_size;
	struct fdtable *fdt;
	/* Allocate small arguments on the stack to save memory and be faster */
	long stack_fds[SELECT_STACK_ALLOC/sizeof(long)];

	ret = -EINVAL;
	if (n < 0)
		goto out_nofds;

	/* max_fds can increase, so grab it once to avoid race */
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
		/* Not enough space in on-stack array; must use kmalloc */
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

	if ((ret = get_fd_set(n, inp, fds.in)) ||
	    (ret = get_fd_set(n, outp, fds.out)) ||
	    (ret = get_fd_set(n, exp, fds.ex)))
		goto out;
	zero_fd_set(n, fds.res_in);
	zero_fd_set(n, fds.res_out);
	zero_fd_set(n, fds.res_ex);

//其实上面的一大坨操作都是在拷贝用户空间的fd_set到内核态，以及安全性检查、初始化之类的工作，最主要的逻辑在do_select中
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

poll_wqueues这个结构体的定义为：
```c
struct poll_wqueues {
	poll_table pt;
	struct poll_table_page *table;
	struct task_struct *polling_task;
	int triggered;
	int error;
	int inline_index;
	struct poll_table_entry inline_entries[N_INLINE_POLL_ENTRIES];
};
```
poll_wqueues指向一个poll_table_page的单链表。

poll_initwait()的定义为：
```c
void poll_initwait(struct poll_wqueues *pwq)
{
	init_poll_funcptr(&pwq->pt, __pollwait); //实际上主要是对poll_table pt进行了初始化，设置了_qproc函数
	pwq->polling_task = current;
	pwq->triggered = 0;
	pwq->error = 0;
	pwq->table = NULL;
	pwq->inline_index = 0;
}
```

```c
    //do_select(int n, fd_set_bits *fds, struct timespec64 *end_time)
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
    // 首先获取需要监控的三类fd_set
        inp = fds->in; outp = fds->out; exp = fds->ex;
        // 初始化用于保存返回值的三类 fd_set对应的unsigned long 数组
        rinp = fds->res_in; routp = fds->res_out; rexp = fds->res_ex;
        // 开始循环遍历覆盖的所有fd
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
                    wait_key_set(wait, in, out, bit,busy_flag);
                    //初始化wait entry, 将其加入到这个fd对应的socket的等待队列中
                    //获取当前socket是否有读，写，异常等事件并返回
                    mask = vfs_poll(f.file, wait);
```
vfs_poll定义在poll.h中：

```c
static inline __poll_t vfs_poll(struct file *file, struct poll_table_struct *pt)
{
	if (unlikely(!file->f_op->poll))
		return DEFAULT_POLLMASK;
	return file->f_op->poll(file, pt);
}
```
每一个文件系统都有自己的操作集合，不同的file poll操作可能会不同，但都会执行poll_wait()，该方法真正执行的便是前面的回调函数__pollwait，把自己挂入等待队列。
如fs/select.c注释所言：

```c
/* Two very simple procedures, poll_wait() and poll_freewait() make all the
 * work.  poll_wait() is an inline-function defined in <linux/poll.h>,
 * as all select/poll functions have to call it to add an entry to the
 * poll table.
 * /
```

```c
static void __pollwait(struct file *filp, wait_queue_head_t *wait_address,
				poll_table *p)
{
    //根据poll_wqueues的成员pt指针p找到所在的poll_wqueues结构指针
	struct poll_wqueues *pwq = container_of(p, struct poll_wqueues, pt);
	struct poll_table_entry *entry = poll_get_entry(pwq);
	if (!entry)
		return;
	entry->filp = get_file(filp);
	entry->wait_address = wait_address;
	entry->key = p->_key;
    //设置entry->wait.func = pollwake
	init_waitqueue_func_entry(&entry->wait, pollwake);
	entry->wait.private = pwq;// 设置private内容为pwq
	add_wait_queue(wait_address, &entry->wait);// 将该pollwake加入到等待链表头
}
```
这里涉及到了等待队列的相关概念。

```c
//do_select()
                    fdput(f);
                    //按位与，看是否有相关事件，有就将res的位设为1，retval++，wait的qproc函数置空
                    if ((mask & POLLIN_SET) && (in & bit)) {
                        res_in |= bit;
                        retval++;
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

        //  当前监控的fd上没有事件发生，也没有超时或中断发生，
         //   将当前进程设置为 TASK_INTERRUPTIBLE， 并调用 schedule
         //   等待事件发生时，对应的socket将当前进程唤醒后，从这里继续运行
		if (!poll_schedule_timeout(&table, TASK_INTERRUPTIBLE, to, slack))
			timed_out = 1;
	}

	poll_freewait(&table);

	return retval;
}

```

### poll

和select()不一样，poll()没有使用低效的三个基于位的文件描述符set，而是采用了一个单独的结构体pollfd数组，由fds指针指向这个数组，这样就避免了select只能监控1024个文件的问题。

poll的系统调用定义在```fs/select.c```中。

```c
SYSCALL_DEFINE3(poll, struct pollfd __user *, ufds, unsigned int, nfds,
		int, timeout_msecs)
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
    //创建大小为256的数组
	long stack_pps[POLL_STACK_ALLOC/sizeof(long)];
    //这里和select的实现不同，poll是使用链表实现的，因此避免了只能监控有限个文件的问题
	struct poll_list *const head = (struct poll_list *)stack_pps;
 	struct poll_list *walk = head;
 	unsigned long todo = nfds;
```

poll_list结构体的定义为：
```c
struct poll_list {
	struct poll_list *next;
	int len;
	struct pollfd entries[0];
};
```
这里有一个诡异的地方是entries字段是一个长度为0的数组，[它的作用与指针相同，但可以方便内存管理](https://www.cnblogs.com/felove2013/articles/4050226.html)。
```c
//do_sys_poll()
	if (nfds > rlimit(RLIMIT_NOFILE))
		return -EINVAL;

	len = min_t(unsigned int, nfds, N_STACK_PPS);
	for (;;) {
		walk->next = NULL;
		walk->len = len;
		if (!len)
			break;
//将用户传入的pollfd数组拷贝到内核空间
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

	poll_initwait(&table);
    //核心逻辑
	fdcount = do_poll(head, &table, end_time);
	poll_freewait(&table);

	for (walk = head; walk; walk = walk->next) {
		struct pollfd *fds = walk->entries;
		int j;

        //将revents值拷贝到用户空间ufds
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
poll的核心逻辑在do_poll中，

```c
static int do_poll(
    struct poll_list *list, //监控的文件列表
    struct poll_wqueues *wait, 
	struct timespec64 *end_time
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
                //此后的逻辑和select十分相像，这里抽象除了一个do_pollfd的函数，用于
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
			if (signal_pending(current))
				count = -ERESTARTNOHAND;
		}
		if (count || timed_out)
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

		if (!poll_schedule_timeout(wait, TASK_INTERRUPTIBLE, to, slack))
			timed_out = 1;
	}
	return count;
}
```

### epoll

select缺点

* 文件描述符个数受限：单进程能够监控的文件描述符的数量存在最大限制，在Linux上一般为1024，可以通过修改宏定义增大上限，但同样存在效率低的弱势;
* 性能衰减严重：IO随着监控的描述符数量增长，其性能会线性下降;

poll缺点

* 从上面看select和poll都需要在返回后，通过遍历文件描述符来获取已经就绪的socket。同时连接的大量客户端在同一时刻可能只有很少的处于就绪状态，因此随着监视的描述符数量的增长，其性能会线性下降。

epoll使用一个文件描述符管理多个描述符，将用户空间的文件描述符的事件存放到内核的一个事件表中，这样在用户空间和内核空间的copy只需一次。epoll机制是Linux最高效的I/O复用机制，在一处等待多个文件句柄的I/O事件。

epoll的系统调用定义在```fs/eventpoll.c```中。

相比select和poll都只有一个方法，epoll有三个系统调用：

```c
int epoll_create(int size)；
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)；
int epoll_wait(int epfd, struct epoll_event * events, int maxevents, int timeout);

struct epoll_event {
    __uint32_t events;
    epoll_data_t data;
};
```

我们先看epoll_create:

```c
SYSCALL_DEFINE1(epoll_create, int, size)
{
	if (size <= 0)
		return -EINVAL;

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

	/* Check the EPOLL_* constant for consistency.  */
	BUILD_BUG_ON(EPOLL_CLOEXEC != O_CLOEXEC);

	if (flags & ~EPOLL_CLOEXEC)
		return -EINVAL;
	/*
	 * Create the internal data structure ("struct eventpoll").
	 */
	error = ep_alloc(&ep);
	if (error < 0)
		return error;
	/*
	 * Creates all the items needed to setup an eventpoll file. That is,
	 * a file structure and a free file descriptor.
	 */
	fd = get_unused_fd_flags(O_RDWR | (flags & O_CLOEXEC));
	if (fd < 0) {
		error = fd;
		goto out_free_ep;
	}
	file = anon_inode_getfile("[eventpoll]", &eventpoll_fops, ep,
				 O_RDWR | (flags & O_CLOEXEC));
	if (IS_ERR(file)) {
		error = PTR_ERR(file);
		goto out_free_fd;
	}
	ep->file = file;
	fd_install(fd, file);
	return fd;

out_free_fd:
	put_unused_fd(fd);
out_free_ep:
	ep_free(ep);
	return error;
}

```

```c
/*
 * The following function implements the controller interface for
 * the eventpoll file that enables the insertion/removal/change of
 * file descriptors inside the interest set.
 */
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
	if (ep_op_has_event(op) &&
	    copy_from_user(&epds, event, sizeof(struct epoll_event)))
		goto error_return;

	error = -EBADF;
	f = fdget(epfd);
	if (!f.file)
		goto error_return;

	/* Get the "struct file *" for the target file */
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
	 */
	epi = ep_find(ep, tf.file, fd);

	error = -EINVAL;
	switch (op) {
	case EPOLL_CTL_ADD:
		if (!epi) {
			epds.events |= EPOLLERR | EPOLLHUP;
			error = ep_insert(ep, &epds, tf.file, fd, full_check);
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



## 参考
- 《深入理解Linux内核》
- 《Linux内核源代码情景分析》
- https://zhuanlan.zhihu.com/p/141447239
- https://www.linuxprobe.com/linux-io-multiplexing.html
- https://zhuanlan.zhihu.com/p/91428595
- http://gityuan.com/2019/01/05/linux-poll-select/
- http://gityuan.com/2019/01/06/linux-epoll/
- https://www.cnblogs.com/alyssaCui/archive/2013/04/01/2993886.html



