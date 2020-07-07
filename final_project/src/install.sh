#!/bin/sh
set -v
rmmod kpage_heat
make clean
make all
insmod kpage_heat.ko