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
这个poll函数是根据file的f_op中的poll定义的，不同的file可能会不同，针对网络通信，poll最终会经过vfs_poll -> file->f_op->poll -> sock_poll -> tcp->poll的路线。

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

poll的系统调用定义在```fs/select.c```中。

```c
SYSCALL_DEFINE3(poll, struct pollfd __user *, ufds, unsigned int, nfds,
		int, timeout_msecs)
{
	struct timespec64 end_time, *to = NULL;
	int ret;

	if (timeout_msecs >= 0) {
		to = &end_time;
		poll_select_set_timeout(to, timeout_msecs / MSEC_PER_SEC,
			NSEC_PER_MSEC * (timeout_msecs % MSEC_PER_SEC));
	}

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

### epoll

epoll的系统调用定义在```fs/eventpoll.c```中。

## 参考
- 《深入理解Linux内核》
- 《Linux内核源代码情景分析》
- https://zhuanlan.zhihu.com/p/141447239
- https://www.linuxprobe.com/linux-io-multiplexing.html
- https://zhuanlan.zhihu.com/p/91428595



