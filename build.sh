#!/bin/sh

${CROSS_COMPILE}gcc -Wno-implicit-function-declaration -Wno-unused-result -shared -fPIC -O2 mem_hook.c -o libmemhook.so -ldl
${CROSS_COMPILE}gcc mem_monitor.c -o monitor
LD_PRELOAD=./libmemhook.so ./monitor
