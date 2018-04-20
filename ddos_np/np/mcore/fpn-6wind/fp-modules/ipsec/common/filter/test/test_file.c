/*
 * Copyright(c) 2007 6WIND
 * $Id: test_file.c,v 1.11 2008-11-28 09:01:31 guerin Exp $
 */
#include "fpn.h"
#include <sys/types.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "filter.h"
#include "test_file.h"

#define NIPQUAD(addr) \
((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

/*
 *
 *	Input Format For Filters:
 *
 * 	@134.32.31.22/30 232.123.222.198/26 2/65535 80/65535 17 1 44
 *
 * 	each filter should start with the @ symbol followed by
 *
 *	SourceIP/Length DestIP/Length SPort/Mask DPort/Mask Proto/Mask Action Cost
 *	
 *	where,
 *	0.0.0.0/0  for IP represents *.*.*.*
 *      integer values and masks format can be decimal/hexa/octal
 */

static void ReadPrefix(FILE *fp, uint32_t *adr, uint8_t *len)
{
	/*assumes IPv4 prefixes*/
	unsigned int tpref[4],templen;

	fscanf(fp,"%d.%d.%d.%d/%d", &tpref[0], &tpref[1], &tpref[2], &tpref[3], &templen);
	if (templen >= 24)
		*adr = (tpref[0] << 24) + (tpref[1] << 16) + (tpref[2] << 8) + (tpref[3]);
	else if (templen >=16) 
		*adr = (tpref[0] << 24) + (tpref[1] << 16) + (tpref[2] << 8);
	else if (templen >= 8)
		*adr = (tpref[0] << 24) + (tpref[1] << 16);
	else if (templen > 0)
		*adr = (tpref[0] << 24);
	else
		*adr = 0;
		
	*adr = htonl(*adr);
	*len = (uint8_t)templen;
}

static void ReadPort(FILE *fp, uint16_t *port, uint16_t *mask)
{
	unsigned int tport;
	unsigned int tmask;

	fscanf(fp,"%i/%i",&tport, &tmask);

	*port = htons(tport);
	*mask = htons(tmask);
}

static inline uint32_t plen2mask(uint8_t plen)
{
    return plen ? htonl(~((1<<(32-plen)) -1)) : 0;
}

static int ReadFilter(FILE *fp,FiltSet filtset, uint32_t line)
{

	char status,validfilter;
	struct FILTER tempfilt1,*tempfilt;
	unsigned int x;
	unsigned int protomask;

	while (1) {
		status = fscanf(fp,"%c",&validfilter);
		if (status == EOF)
			return -1;
		if (validfilter != '@')
			continue;	

		tempfilt = &tempfilt1;

		ReadPrefix(fp, &tempfilt->src, &tempfilt->src_plen);
		ReadPrefix(fp, &tempfilt->dst, &tempfilt->dst_plen);

		tempfilt->src_mask = plen2mask(tempfilt->src_plen);
		tempfilt->dst_mask = plen2mask(tempfilt->dst_plen);
#if 0
		printf("src=%u.%u.%u.%u dst=%u.%u.%u.%u\n",
				NIPQUAD(tempfilt->src), NIPQUAD(tempfilt->dst));

#endif
		ReadPort(fp,&(tempfilt->srcport),&(tempfilt->srcport_mask));
		ReadPort(fp,&(tempfilt->dstport),&(tempfilt->dstport_mask));

		fscanf(fp, "%i/%i", &x, &protomask);
		if (protomask == 0xFF)
			tempfilt->ul_proto = (uint8_t)x;
		else
			tempfilt->ul_proto = 0xFF;
		
		
		tempfilt->vrfid = 0;
		tempfilt->filtId = line-1;
		tempfilt->cost = 0;
		tempfilt->action = 0;

		memcpy(&(filtset->filtArr[filtset->numFilters]), tempfilt, sizeof(struct FILTER));
		filtset->numFilters++;	

		break;
	}

	return 0;
}

static void LoadFilters(FILE *fp, struct FILTSET *filtset, unsigned int max)
{
	int line = 0;

	filtset->numFilters=0;

	while ( (!(feof(fp))) && (filtset->numFilters < max))
	{
		line++;
		if (ReadFilter(fp,filtset,line) < 0)
			break;
	}
}

int LoadFilters_from_file(char *filename, struct FILTSET *filtset, int max)
{
	FILE *fp;

	fp = fopen(filename,"r");

	if (fp==NULL)
		return -1;

	LoadFilters(fp, filtset, max);

	fclose(fp);

	return 0;
}
