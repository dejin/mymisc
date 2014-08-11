#include <stdio.h>
#include <stdlib.h>

//#define dbg(...)  printf(__VA_ARGS__)
#define dbg(fmt, ...) printf(fmt, ## __VA_ARGS__)

int main(void)
{
	int a =5;
	int b = 9;

	dbg("test\n");
	dbg("test a[%d]\n", a);
	dbg("test a[%d] b{%d}\n", a, b);
	return 0;
}
