/* hello2.c */
#include <stdio.h>

int g_y = 1;

void bar() {
	g_y = 2;
}

void foo2() {
	bar();
	printf("foo2:g_y = %d\n", g_y);
}

