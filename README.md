# LinuxKernel
Linux Kernel Course Projects in SJTU

## Project 1
* module1: wirte a module which whill print "hello" in the kernel log when you insert it and "goodbye" when you remove it.
* module2: write a module which accepts variables in type ```int, char*, int[]``` and prints the value of those variables in the kernel log when you insert it.
* module3: write a module which will create a read-only proc file.
* module4: wirte a module which will create a proc directory and a read-write file in it.

The answer to project1 is in ```project1/src```. Specifically, ```project1/src/hello.c``` is for module1, ```project1/src/param.c``` is for module2, ```project1/src/proc_r.c``` is for module3 and ```project1/src/proc_rw.c``` is for module4.

## Project 2

* add ```ctx``` to ```task_struct``` to count the CPU scheduling times of the process
* create ```/proc/<PID>/ctx``` to get the value of ```ctx```

The answer to project2 is in ```project2/report```
