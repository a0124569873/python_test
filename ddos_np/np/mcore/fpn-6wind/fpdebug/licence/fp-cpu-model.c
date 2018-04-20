
#include <stdint.h>
#include <stdio.h>

struct cpuid_result {
	uint32_t eax;
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;
};

static inline struct cpuid_result cpuid(uint32_t op) ;
uint32_t get_cpu_name(char* buffer, uint32_t size);


static inline struct cpuid_result cpuid(uint32_t op) {
	struct cpuid_result result;
	asm volatile(
		"mov %%ebx, %%edi;"
		"cpuid;"
		"mov %%ebx, %%esi;"
		"mov %%edi, %%ebx;"
		: "=a" (result.eax),
		  "=S" (result.ebx),
		  "=c" (result.ecx),
		  "=d" (result.edx)
		: "0" (op)
		: "edi");
	return result;
}

uint32_t get_cpu_name(char* buffer, uint32_t size) {
	struct cpuid_result regs;
	char temp_processor_name[49];
	char* processor_name_start;
	uint32_t* name_as_ints = (uint32_t *)temp_processor_name;
	uint32_t i;

	/* 
	用cpuid指令，eax传入0x80000002/0x80000003/0x80000004，
	共3个，每个4个寄存器，每个寄存器4字节，故一共48字节。
	参考IA32开发手册第2卷第3章。
	*/
	for (i = 0; i < 3; i++) {
		regs = cpuid(0x80000002 + i);
		name_as_ints[i * 4 + 0] = regs.eax;
		name_as_ints[i * 4 + 1] = regs.ebx;
		name_as_ints[i * 4 + 2] = regs.ecx;
		name_as_ints[i * 4 + 3] = regs.edx;
	}

	temp_processor_name[48] = 0;

	/* Skip leading spaces. */
	processor_name_start = temp_processor_name;
	while (*processor_name_start == ' ')
		processor_name_start++;

    return snprintf(buffer, size, "%s", processor_name_start);
}