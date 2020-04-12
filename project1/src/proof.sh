#!/bin/sh 
set -v
make > /dev/null 2>&1
############ test module1 #################
insmod hello.ko
rmmod hello.ko
dmesg | tail -10 | grep "module1"
############ test module2 #################
insmod param.ko int_var=666 str_var=sunchenge int_arr_var=5,1,6,0,3,0,9,1,0,4,2,1
rmmod param.ko
dmesg | tail -20 | grep "module2"
############ test module3 #################
insmod proc_r.ko
cat /proc/proc_r
rmmod proc_r
############ test module4 #################
sudo insmod proc_rw.ko
cat /proc/proc_rw_dir/proc_rw
echo "hello proc file" > /proc/proc_rw_dir/proc_rw
cat /proc/proc_rw_dir/proc_rw
echo "666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666" > /proc/proc_rw_dir/proc_rw
cat /proc/proc_rw_dir/proc_rw
rmmod proc_rw
########### dmesg ############
dmesg | tail -50 | grep "module[1-4]"> proof_message.txt
