#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void gen_file(unsigned int count, int trace)
{
	unsigned char a=1,b=1;//,c=1,d=1;
	unsigned int z1 = 10, z2 = 20;
	unsigned int i, addr1, addr2;

	for (i = 0 ; i < count; i++) {
		if (trace) {
			addr1 = (z1 << 24) + (a<<16) +(b<<8) + 1;
			addr2 = (z2 << 24) + (a<<16) +(b<<8) + 1;
			printf("%u %u 4000 5000 6 %u\n", addr1, addr2, i+1);
		} else {
			printf("@%u.%u.%u.%u/24 %u.%u.%u.%u/24 0 : 65535 0 : 65535 0x06/0xFF\n",
					z1,a,b,0, z2,a,b,0);
		}
		b++;
		if (b == 255) {
			a++;
			b = 1;
		}
		if (a == 255) {
			z1++;
			z2++;
			a = 1;
		}
	}
}
		
static void usage(void)
{
	fprintf(stderr, "gen2d -n <num> to generate ruleset with <num> rules\n");
	fprintf(stderr, "gen2d -n <num> -t to generate trace matching each rule\n");
	exit(1);
}

int main(int argc, char **argv)
{
	int opt;
	unsigned int count = 0;
	int trace = 0;
	while ((opt = getopt(argc, argv, "n:t")) != -1) {
		switch(opt) {
		case 'n':
			count = atoi(optarg);
			break;
		case 't':
			trace = 1;
			break;
		default:
			usage();
		}
	}
	gen_file(count, trace);

	return 0;
}
	
