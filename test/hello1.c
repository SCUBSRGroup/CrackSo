/* hello1.c */
#include <stdio.h>

int g_a = 1;
int g_b = 2;
int g_x;

extern bar();
extern foo2();

#if !defined(APP)
void foo();
#endif

void my_init() {
	printf("hello world from my_init\r\n");
	foo();
	foo2();
}

#if !defined(APP)
extern int g_y;
void foo() {
#else
int main() {
#endif
	int a = 3;
	int b = 4;
	g_x = a + g_a;
	printf("foo:a = %d\nb = %d\ng_x=%d\n", a, b, g_x);
	return;
}



