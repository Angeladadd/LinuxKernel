#!/usr/bin/bash
set -v
diff -Nrup origin/sched.h sched.h
diff -Nrup origin/fork.c fork.c
diff -Nrup origin/core.c core.c
diff -Nrup origin/base.c base.c
