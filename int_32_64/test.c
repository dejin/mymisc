#include <stdio.h>
#include <inttypes.h>

int main(void)
{
	int32_t aa;
	aa = 5;
	printf("aa = %d\n", aa);
	uint64_t bb = 9;
	printf("bb = %"PRIu64"\n", bb);
	return 0;
}
