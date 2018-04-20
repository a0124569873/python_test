/*
 * Copyright(c) 2010 6WIND
 */
#include "fpn.h"
#include "fpn-hexdump.h"

void fpn_hexdump(const char *title, const void *buf, unsigned int len)
{
	unsigned int i, out, ofs;
	const unsigned char *data = buf;
#define LINE_LEN 80
	char line[LINE_LEN];	/* space needed 8+16*3+3+16 == 75 */

	fpn_printf("%s at [%p], len=%d\n", title, data, len);
	ofs = 0;
	while (ofs < len) {
		/* format 1 line in the buffer, then use printk to print them */
		out = snprintf(line, LINE_LEN, "%08X", ofs);
		for (i=0; ofs+i < len && i<16; i++)
			out += snprintf(line+out, LINE_LEN - out, " %02X", data[ofs+i]&0xff);
		for(;i<=16;i++)
			out += snprintf(line+out, LINE_LEN - out, "   ");
		for(i=0; ofs < len && i<16; i++, ofs++) {
			unsigned char c = data[ofs];
			if (!isascii(c) || !isprint(c))
				c = '.';
			out += snprintf(line+out, LINE_LEN - out, "%c", c);
		}
		fpn_printf("%s\n", line);
	}
}

