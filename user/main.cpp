#include "kernel.h"

int main(int argc,char **argv)
{
	//driver->init_key("paste your driver verify key here");
	PACKAGENAME* bm="com.tencent.tmgp.sgame";
	getPID(bm);
	printf("pid = %d\n", pid);
	uint64_t add=getModuleBase("libunity.so");
	printf("base = %lX\n", add);

	uint64_t add1=ReadValue(add+0x0);
	printf("指针 = %lX\n",add1);

	int add2=ReadDword(add+0x0);
	printf("D类型 = %d\n",add2);

	float add3=ReadFloat(add+0x0);
	printf("F类型 = %f\n",add3);

	//WriteDword(add, 16384);
	//WriteFloat(add, 16384);
}