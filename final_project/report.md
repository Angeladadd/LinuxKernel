# <center>Linux Kernel Final Report

<center>孙晨鸽 516030910421</center>

## 实验过程

* 内核版本 ： 5.5.9
* 平台: 华为云 x 鲲鹏通用计算增强型 | kc1.large.2 | 2vCPUs | 4GB x Ubuntu 18.04 64bit with ARM

### 计算页热度

[由pid获取task_struct](https://tuxthink.blogspot.com/2012/07/module-to-find-task-from-its-pid.html?m=1)

[数据、堆段对应的vma列表](https://www.cnblogs.com/arnoldlu/p/10272466.html) (数据段不知道怎么回事，一直没数据，堆是可以的)


### debug

* 实时监控dmesg : ```dmesg -wH```