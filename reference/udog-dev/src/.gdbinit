#filename dk-client-debug
target remote:1234
file "~/workspace/udog/src/udog.out"
b main
c
