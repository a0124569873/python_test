/*
 * Copyright(c) 2013 6WIND, All rights reserved.
 */

/*-
 *   BSD LICENSE
 * 
 *   Copyright(c) 2010-2013 Intel Corporation. All rights reserved.
 *   All rights reserved.
 * 
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 * 
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "fpn.h"
#include "fpn-sw-sched.h"

#include <rte_string_fns.h>
#include <rte_sched.h>

/* from cfg_file.h */
#define CFG_NAME_LEN 32
#define CFG_VALUE_LEN 64

struct cfg_entry {
	char name[CFG_NAME_LEN];
	char value[CFG_VALUE_LEN];
};

struct cfg_section {
	char name[CFG_NAME_LEN];
	int num_entries;
	struct cfg_entry *entries[0];
};

struct cfg_file {
	int flags;
	int num_sections;
	struct cfg_section *sections[0];
};
/* end from cfg_file.h */

/* from main.h */
static int cfg_close(struct cfg_file *cfg);
#define MAX_SCHED_SUBPORTS		8
#define MAX_SCHED_PIPES			8192 /* per subport (x8) */
/* end from main.h */

/* from init.c */
int app_pipe_to_profile[MAX_SCHED_SUBPORTS][MAX_SCHED_PIPES];

static struct rte_sched_subport_params subport_params[MAX_SCHED_SUBPORTS] = {
	{
		.tb_rate = 1250000000,
		.tb_size = 1000000,

		.tc_rate = {1250000000, 1250000000, 1250000000, 1250000000},
		.tc_period = 10,
	},
};

static struct rte_sched_pipe_params pipe_profiles[RTE_SCHED_PIPE_PROFILES_PER_PORT] = {
	{ /* Profile #0 */
		.tb_rate = 305175,
		.tb_size = 1000000,

		.tc_rate = {305175, 305175, 305175, 305175},
		.tc_period = 40,
		.wrr_weights = {1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1},
	},
};

struct rte_sched_port_params port_params = {
	.name = "port_scheduler_0",
	.socket = 0, /* computed */
	.rate = 0, /* computed */
	.mtu = 6 + 6 + 4 + 4 + 2 + 1500,
	.frame_overhead = RTE_SCHED_FRAME_OVERHEAD_DEFAULT,
	.n_subports_per_port = 1,
	.n_pipes_per_subport = 4096,
	.qsize = {64, 64, 64, 64},
	.pipe_profiles = pipe_profiles,
	.n_pipe_profiles = sizeof(pipe_profiles) / sizeof(struct rte_sched_pipe_params),
};

/* end from init.c */

/** when we resize a file structure, how many extra entries
 * for new sections do we add in */
#define CFG_ALLOC_SECTION_BATCH 8
/** when we resize a section structure, how many extra entries
 * for new entries do we add in */
#define CFG_ALLOC_ENTRY_BATCH 16

static unsigned
_strip(char *str, unsigned len)
{
	int newlen = len;
	if (len == 0)
		return 0;

	if (isspace(str[len-1])) {
		/* strip trailing whitespace */
		while (newlen > 0 && isspace(str[newlen - 1]))
			str[--newlen] = '\0';
	}

	if (isspace(str[0])) {
		/* strip leading whitespace */
		int i,start = 1;
		while (isspace(str[start]) && start < newlen)
			start++
			; /* do nothing */
		newlen -= start;
		for (i = 0; i < newlen; i++)
			str[i] = str[i+start];
		str[i] = '\0';
	}
	return newlen;
}

static
struct cfg_file *
cfg_load(const char *filename, int flags)
{
	int allocated_sections = CFG_ALLOC_SECTION_BATCH;
	int allocated_entries = 0;
	int curr_section = -1;
	int curr_entry = -1;
	char buffer[256];
	int lineno = 0;
	struct cfg_file *cfg = NULL;

	FILE *f = fopen(filename, "r");
	if (f == NULL)
		return NULL;

	cfg = malloc(sizeof(*cfg) +	sizeof(cfg->sections[0]) * allocated_sections);
	if (cfg == NULL)
		goto error2;

	memset(cfg->sections, 0, sizeof(cfg->sections[0]) * allocated_sections);

	while (fgets(buffer, sizeof(buffer), f) != NULL) {
		char *pos = NULL;
		size_t len = strnlen(buffer, sizeof(buffer));
		lineno++;
		if (len >=sizeof(buffer) - 1 && buffer[len-1] != '\n'){
			fpn_printf("Error line %d - no \\n found on string. "
					"Check if line too long\n", lineno);
			goto error1;
		}
		if ((pos = memchr(buffer, ';', sizeof(buffer))) != NULL) {
			*pos = '\0';
			len = pos -  buffer;
		}

		len = _strip(buffer, len);
		if (buffer[0] != '[' && memchr(buffer, '=', len) == NULL)
			continue;

		if (buffer[0] == '[') {
			/* section heading line */
			char *end = memchr(buffer, ']', len);
			if (end == NULL) {
				fpn_printf("Error line %d - no terminating '[' found\n", lineno);
				goto error1;
			}
			*end = '\0';
			_strip(&buffer[1], end - &buffer[1]);

			/* close off old section and add start new one */
			if (curr_section >= 0)
				cfg->sections[curr_section]->num_entries = curr_entry + 1;
			curr_section++;

			/* resize overall struct if we don't have room for more sections */
			if (curr_section == allocated_sections) {
				allocated_sections += CFG_ALLOC_SECTION_BATCH;
				struct cfg_file *n_cfg = realloc(cfg, sizeof(*cfg) +
						sizeof(cfg->sections[0]) * allocated_sections);
				if (n_cfg == NULL) {
					fpn_printf("Error - no more memory\n");
					goto error1;
				}
				cfg = n_cfg;
			}

			/* allocate space for new section */
			allocated_entries = CFG_ALLOC_ENTRY_BATCH;
			curr_entry = -1;
			cfg->sections[curr_section] = malloc(sizeof(*cfg->sections[0]) +
					sizeof(cfg->sections[0]->entries[0]) * allocated_entries);
			if (cfg->sections[curr_section] == NULL) {
				fpn_printf("Error - no more memory\n");
				goto error1;
			}

			snprintf(cfg->sections[curr_section]->name,
				 sizeof(cfg->sections[0]->name),
				 "%s", &buffer[1]);
		}
		else {
			/* value line */
			if (curr_section < 0) {
				fpn_printf("Error line %d - value outside of section\n", lineno);
				goto error1;
			}

			struct cfg_section *sect = cfg->sections[curr_section];
			char *split[2];
			if (rte_strsplit(buffer, sizeof(buffer), split, 2, '=') != 2) {
				fpn_printf("Error at line %d - cannot split string\n", lineno);
				goto error1;
			}

			curr_entry++;
			if (curr_entry == allocated_entries) {
				allocated_entries += CFG_ALLOC_ENTRY_BATCH;
				struct cfg_section *n_sect = realloc(sect, sizeof(*sect) +
						sizeof(sect->entries[0]) * allocated_entries);
				if (n_sect == NULL) {
					fpn_printf("Error - no more memory\n");
					goto error1;
				}
				sect = cfg->sections[curr_section] = n_sect;
			}

			sect->entries[curr_entry] = malloc(sizeof(*sect->entries[0]));
			if (sect->entries[curr_entry] == NULL) {
				fpn_printf("Error - no more memory\n");
				goto error1;
			}

			struct cfg_entry *entry = sect->entries[curr_entry];
			snprintf(entry->name, sizeof(entry->name), "%s", split[0]);
			snprintf(entry->value, sizeof(entry->value), "%s", split[1]);
			_strip(entry->name, strnlen(entry->name, sizeof(entry->name)));
			_strip(entry->value, strnlen(entry->value, sizeof(entry->value)));
		}
	}
	fclose(f);
	cfg->flags = flags;
	if (cfg->sections[curr_section]) {
		cfg->sections[curr_section]->num_entries = curr_entry + 1;
		cfg->num_sections = curr_section + 1;
	}
	return cfg;

error1:
	cfg_close(cfg);
error2:
	fclose(f);
	return NULL;
}


static
int cfg_close(struct cfg_file *cfg)
{
	int i, j;

	if (cfg == NULL)
		return -1;

	for(i = 0; i < cfg->num_sections; i++) {
		if (cfg->sections[i] != NULL) {
			if (cfg->sections[i]->num_entries) {
				for(j = 0; j < cfg->sections[i]->num_entries; j++) {
					if (cfg->sections[i]->entries[j] != NULL)
						free(cfg->sections[i]->entries[j]);
				}
			}
			free(cfg->sections[i]);
		}
	}
	free(cfg);

	return 0;
}

static
int
cfg_num_sections(struct cfg_file *cfg, const char *sectionname, size_t length)
{
	int i;
	int num_sections = 0;
	for (i = 0; i < cfg->num_sections; i++) {
		if (strncmp(cfg->sections[i]->name, sectionname, length) == 0)
			num_sections++;
	}
	return num_sections;
}

static const struct cfg_section *
_get_section(struct cfg_file *cfg, const char *sectionname)
{
	int i;
	for (i = 0; i < cfg->num_sections; i++) {
		if (strncmp(cfg->sections[i]->name, sectionname,
				sizeof(cfg->sections[0]->name)) == 0)
			return cfg->sections[i];
	}
	return NULL;
}

static
int
cfg_has_section(struct cfg_file *cfg, const char *sectionname)
{
	return (_get_section(cfg, sectionname) != NULL);
}

static
int
cfg_section_num_entries(struct cfg_file *cfg, const char *sectionname)
{
	const struct cfg_section *s = _get_section(cfg, sectionname);
	if (s == NULL)
		return -1;
	return s->num_entries;
}


static
int
cfg_section_entries(struct cfg_file *cfg, const char *sectionname,
		struct cfg_entry *entries, int max_entries)
{
	int i;
	const struct cfg_section *sect = _get_section(cfg, sectionname);
	if (sect == NULL)
		return -1;
	for (i = 0; i < max_entries && i < sect->num_entries; i++)
		entries[i] = *sect->entries[i];
	return i;
}

static
const char *
cfg_get_entry(struct cfg_file *cfg, const char *sectionname,
		const char *entryname)
{
	int i;
	const struct cfg_section *sect = _get_section(cfg, sectionname);
	if (sect == NULL)
		return NULL;
	for (i = 0; i < sect->num_entries; i++)
		if (strncmp(sect->entries[i]->name, entryname, CFG_NAME_LEN) == 0)
			return sect->entries[i]->value;
	return NULL;
}

static
int
cfg_load_port(struct cfg_file *cfg, struct rte_sched_port_params *port_params)
{
	const char *entry;
	int j;

	if (!cfg || !port_params)
		return -1;

	entry = cfg_get_entry(cfg, "port", "rate");
	if (entry)
		port_params->rate = (uint32_t)atoi(entry);

	entry = cfg_get_entry(cfg, "port", "frame overhead");
	if (entry)
		port_params->frame_overhead = (uint32_t)atoi(entry);

	entry = cfg_get_entry(cfg, "port", "number of subports per port");
	if (entry)
		port_params->n_subports_per_port = (uint32_t)atoi(entry);
	
	entry = cfg_get_entry(cfg, "port", "number of pipes per subport");
	if (entry)
		port_params->n_pipes_per_subport = (uint32_t)atoi(entry);

	entry = cfg_get_entry(cfg, "port", "queue sizes");
	if (entry) {
		char *next;
		
		for(j = 0; j < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; j++) {
			port_params->qsize[j] = (uint16_t)strtol(entry, &next, 10);
			if (next == NULL)
				break;
			entry = next;
		}
	}

	return 0;
}

static
int
cfg_load_pipe(struct cfg_file *cfg, struct rte_sched_pipe_params *pipe_params)
{
	int i, j;
	char *next;
	const char *entry;
	int profiles;

	if (!cfg || !pipe_params)
		return -1;

	profiles = cfg_num_sections(cfg, "pipe profile", sizeof("pipe profile") - 1);
	port_params.n_pipe_profiles = profiles;

	for (j = 0; j < profiles; j++) {
		char pipe_name[32];
		snprintf(pipe_name, sizeof(pipe_name), "pipe profile %d", j);

		entry = cfg_get_entry(cfg, pipe_name, "tb rate");
		if (entry)
			pipe_params[j].tb_rate = (uint32_t)atoi(entry);

		entry = cfg_get_entry(cfg, pipe_name, "tb size");
		if (entry)
			pipe_params[j].tb_size = (uint32_t)atoi(entry);

		entry = cfg_get_entry(cfg, pipe_name, "tc period");
		if (entry)
			pipe_params[j].tc_period = (uint32_t)atoi(entry);

		entry = cfg_get_entry(cfg, pipe_name, "tc 0 rate");
		if (entry)
			pipe_params[j].tc_rate[0] = (uint32_t)atoi(entry);
			
		entry = cfg_get_entry(cfg, pipe_name, "tc 1 rate");
		if (entry)
			pipe_params[j].tc_rate[1] = (uint32_t)atoi(entry);
			
		entry = cfg_get_entry(cfg, pipe_name, "tc 2 rate");
		if (entry)
			pipe_params[j].tc_rate[2] = (uint32_t)atoi(entry);
			
		entry = cfg_get_entry(cfg, pipe_name, "tc 3 rate");
		if (entry)
			pipe_params[j].tc_rate[3] = (uint32_t)atoi(entry);

#ifdef RTE_SCHED_SUBPORT_TC_OV
		entry = cfg_get_entry(cfg, pipe_name, "tc 3 oversubscription weight");
		if (entry)
			pipe_params[j].tc_ov_weight = (uint8_t)atoi(entry);
#endif

		entry = cfg_get_entry(cfg, pipe_name, "tc 0 wrr weights");
		if (entry) {
			for(i = 0; i < RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS; i++) {
				pipe_params[j].wrr_weights[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE*0 + i] =
					(uint8_t)strtol(entry, &next, 10);
				if (next == NULL)
					break;
				entry = next;
			}
		}
		entry = cfg_get_entry(cfg, pipe_name, "tc 1 wrr weights");
		if (entry) {
			for(i = 0; i < RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS; i++) {
				pipe_params[j].wrr_weights[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE*1 + i] =
					(uint8_t)strtol(entry, &next, 10);
				if (next == NULL)
					break;
				entry = next;
			}
		}
		entry = cfg_get_entry(cfg, pipe_name, "tc 2 wrr weights");
		if (entry) {
			for(i = 0; i < RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS; i++) {
				pipe_params[j].wrr_weights[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE*2 + i] =
					(uint8_t)strtol(entry, &next, 10);
				if (next == NULL)
					break;
				entry = next;
			}
		}
		entry = cfg_get_entry(cfg, pipe_name, "tc 3 wrr weights");
		if (entry) {
			for(i = 0; i < RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS; i++) {
				pipe_params[j].wrr_weights[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE*3 + i] =
					(uint8_t)strtol(entry, &next, 10);
				if (next == NULL)
					break;
				entry = next;
			}
		}
	}
	return 0;
}

static
int
cfg_load_subport(struct cfg_file *cfg, struct rte_sched_subport_params *subport_params)
{
	const char *entry;
	int i, j, k;

	if (!cfg || !subport_params)
		return -1;

	memset(app_pipe_to_profile, -1, sizeof(app_pipe_to_profile));

	for (i = 0; i < MAX_SCHED_SUBPORTS; i++) {
		char sec_name[CFG_NAME_LEN];
		snprintf(sec_name, sizeof(sec_name), "subport %d", i);

		if (cfg_has_section(cfg, sec_name)) {
			entry = cfg_get_entry(cfg, sec_name, "tb rate");
			if (entry)
				subport_params[i].tb_rate = (uint32_t)atoi(entry);

			entry = cfg_get_entry(cfg, sec_name, "tb size");
			if (entry)
				subport_params[i].tb_size = (uint32_t)atoi(entry);

			entry = cfg_get_entry(cfg, sec_name, "tc period");
			if (entry)
				subport_params[i].tc_period = (uint32_t)atoi(entry);

			entry = cfg_get_entry(cfg, sec_name, "tc 0 rate");
			if (entry)
				subport_params[i].tc_rate[0] = (uint32_t)atoi(entry);

			entry = cfg_get_entry(cfg, sec_name, "tc 1 rate");
			if (entry)
				subport_params[i].tc_rate[1] = (uint32_t)atoi(entry);

			entry = cfg_get_entry(cfg, sec_name, "tc 2 rate");
			if (entry)
				subport_params[i].tc_rate[2] = (uint32_t)atoi(entry);

			entry = cfg_get_entry(cfg, sec_name, "tc 3 rate");
			if (entry)
				subport_params[i].tc_rate[3] = (uint32_t)atoi(entry);

			int n_entries = cfg_section_num_entries(cfg, sec_name);
			struct cfg_entry entries[n_entries];

			cfg_section_entries(cfg, sec_name, entries, n_entries);

			for (j = 0; j < n_entries; j++) {
				if (strncmp("pipe", entries[j].name, sizeof("pipe") - 1) == 0) {
					int profile;
					char *tokens[2] = {NULL, NULL};
					int n_tokens;
					int begin, end;

					profile = atoi(entries[j].value);
					n_tokens = rte_strsplit(&entries[j].name[sizeof("pipe")],
							strnlen(entries[j].name, CFG_NAME_LEN), tokens, 2, '-');

					begin =  atoi(tokens[0]);
					if (n_tokens == 2)
						end = atoi(tokens[1]);
					else
						end = begin;

					if (end >= MAX_SCHED_PIPES || begin > end)
						return -1;

					for (k = begin; k <= end; k++) {
						char profile_name[CFG_NAME_LEN];

						snprintf(profile_name, sizeof(profile_name),
							 "pipe profile %d", profile);
						if (cfg_has_section(cfg, profile_name))
							app_pipe_to_profile[i][k] = profile;
						else {
							fpn_printf("Wrong pipe profile %s\n", entries[j].value);
							return -1;
						}

					}
				}
			}
		}
	}

	return 0;
}

/* Now, only 6WIND stuff */
typedef struct fpn_sw_sched_rte_port {
	void *sched;
	uint32_t subports_mask;
	uint32_t pipes_mask;
	uint64_t default_class;
	uint64_t invalid_class;
} fpn_sw_sched_rte_port_t;

typedef struct fpn_sw_sched_rte_cpu {
	fpn_sw_sched_rte_port_t ports[FPN_MAX_PORTS];
} fpn_sw_sched_rte_cpu_t __fpn_cache_aligned;

static fpn_sw_sched_rte_cpu_t sched_rte_port[FPN_MAX_CORES];

void *fpn_sw_sched_allocate(fpn_sw_sched_params_t *params)
{
	struct cfg_file *cfg_file = NULL;
	fpn_sw_sched_rte_port_t *tmp, *port = NULL;
	uint32_t subport;

	if (!params)
		goto end;

	tmp = &sched_rte_port[params->core].ports[params->port];
	if (tmp->sched)
		goto end;

	if (!(cfg_file = cfg_load((char *)params->arg, 0))) {
		fpn_printf("Cannot load configuration profile %s\n", (char *)params->arg);
		goto end;
	}

	port_params.name = params->name;
	port_params.socket = rte_lcore_to_socket_id(params->core);
	port_params.rate = (uint64_t) 10 * 1000 * 1000 * 1000 / 8;

	if (cfg_load_port(cfg_file, &port_params)) {
		fpn_printf("Cannot load port parameters from file %s\n", (char *)params->arg);
		goto end;
	}

	if (cfg_load_subport(cfg_file, subport_params)) {
		fpn_printf("Cannot load subport parameters from file %s\n", (char *)params->arg);
		goto end;
	}

	if (cfg_load_pipe(cfg_file, pipe_profiles)) {
		fpn_printf("Cannot load pipe parameters from file %s\n", (char *)params->arg);
		goto end;
	}

	if (!(tmp->sched = rte_sched_port_config(&port_params))) {
		fpn_printf("Unable to config sched port\n");
		goto end;
	}

	for (subport = 0; subport < port_params.n_subports_per_port; subport ++) {
		uint32_t pipe;
		int err = rte_sched_subport_config(tmp->sched, subport, &subport_params[subport]);

		if (err) {
			fpn_printf("Unable to config sched subport %u, err=%d\n", subport, err);
			break;
		}

		for (pipe = 0; pipe < port_params.n_pipes_per_subport; pipe ++) {
			if (app_pipe_to_profile[subport][pipe] != -1) {
				err = rte_sched_pipe_config(tmp->sched, subport, pipe, app_pipe_to_profile[subport][pipe]);
				if (err) {
					fpn_printf("Unable to config sched pipe %u for profile %d, err=%d\n", pipe, app_pipe_to_profile[subport][pipe], err);
					break;
				}
			}
		}

		if (pipe < port_params.n_pipes_per_subport)
			break;
	}

	/* ok, ready */
	if (subport == port_params.n_subports_per_port) {
		/* dpdk 1.5.1 ensure that n_subports_per_port and
		 * n_pipes_per_subport are a power of 2 */
		tmp->subports_mask = port_params.n_subports_per_port - 1;
		tmp->pipes_mask = port_params.n_pipes_per_subport - 1;
		port = tmp;
	}

end:
	if (cfg_file)
		cfg_close(cfg_file);

	return port;
}

/*
 * One interesting point is that dpdk stores class in the same field as rss/fdir
 * hash. This way, fast path has a default mark to use.
 */
uint32_t fpn_sw_sched_default_class(void *sw_port, struct mbuf *m)
{
	fpn_sw_sched_rte_port_t *port = sw_port;
	struct rte_mbuf *rtem = (struct rte_mbuf *)m;
	
#if BUILT_DPDK_VERSION > DPDK_VERSION(1, 7, 1)
	union {
		struct rte_sched_port_hierarchy h;
		uint64_t class;
	} tmp;

	tmp.class = (uint64_t)(((uint64_t)MBUF_DPDK_HASH(rtem).sched.hi << 32) | MBUF_DPDK_HASH(rtem).sched.lo);
#else
	union {
		struct rte_sched_port_hierarchy h;
		uint32_t class;
	} tmp;

	tmp.class = MBUF_DPDK_HASH(rtem).sched;
#endif

	tmp.h.subport &= port->subports_mask;
	tmp.h.pipe &= port->pipes_mask;
	port->default_class++;

	return tmp.class;
}

/* if user sends an invalid class, then defaults to 0 */
int fpn_sw_sched_classify(void *sw_port, struct mbuf *m, uint32_t class)
{
	fpn_sw_sched_rte_port_t *port = sw_port;
	struct rte_mbuf *rtem = (struct rte_mbuf *)m;
#if BUILT_DPDK_VERSION > DPDK_VERSION(1, 7, 1)
	union {
		struct rte_sched_port_hierarchy h;
		uint64_t class;
	} tmp;

	tmp.class = class;

	if (unlikely((tmp.h.subport & (~port->subports_mask)) ||
		(tmp.h.pipe & (~port->pipes_mask)))) {
		tmp.h.subport = 0;
		tmp.h.pipe = 0;
		port->invalid_class++;
	}	
	MBUF_DPDK_HASH(rtem).sched.hi = ((tmp.class >> 32) & 0xFFFFFFFF);	
	MBUF_DPDK_HASH(rtem).sched.lo = ((tmp.class) & 0xFFFFFFFF);
#else
	union {
		struct rte_sched_port_hierarchy h;
		uint32_t class;
	} tmp;

	tmp.class = class;
	if (unlikely((tmp.h.subport & (~port->subports_mask)) ||
	             (tmp.h.pipe & (~port->pipes_mask)))) {
		tmp.h.subport = 0;
		tmp.h.pipe = 0;
		port->invalid_class++;
	}

	MBUF_DPDK_HASH(rtem).sched = tmp.class;
#endif
	

	return 0;
}

int fpn_sw_sched_enqueue(void *sw_port, struct mbuf **pkts, int nbpkts)
{
	fpn_sw_sched_rte_port_t *port = sw_port;

	return rte_sched_port_enqueue(port->sched, (struct rte_mbuf **)pkts,
	                              nbpkts);
}

int fpn_sw_sched_dequeue(void *sw_port, struct mbuf **pkts, int nbpkts)
{
	fpn_sw_sched_rte_port_t *port = sw_port;

	return rte_sched_port_dequeue(port->sched, (struct rte_mbuf **)pkts,
	                              nbpkts);
}

#define FPN_SW_SCHED_RTE_STATS
#ifdef FPN_SW_SCHED_RTE_STATS
static inline int dump_pipe_stats(fpn_sw_sched_rte_port_t *port, uint32_t sp,
                                   uint32_t pipe)
{
	const uint32_t q_per_pipe = RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE *
	                            RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS;
	uint32_t offset = q_per_pipe * (sp * (port->pipes_mask + 1) + pipe);
	uint32_t queue;
	uint32_t count = 0;

	for (queue = 0; queue < q_per_pipe; queue++) {
		struct rte_sched_queue_stats stats;
		uint16_t qlen;

		rte_sched_queue_read_stats(port->sched, offset + queue, &stats, &qlen);

		if (qlen) {
			fpn_printf("|%2d|%10d|%2d|%2d|%11" PRIu32 "|%11" PRIu32
			           "|%11" PRIu32 "|%11" PRIu32 "|%11i|\n",
			           sp, pipe,
			           queue / RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
			           queue % RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS,
			           stats.n_pkts, stats.n_pkts_dropped,
			           stats.n_bytes, stats.n_bytes_dropped, qlen);
			count++;
		}
	}

	return count;
}

static inline int dump_subport_stats(fpn_sw_sched_rte_port_t *port, uint32_t sp)
{
	uint32_t pipe;
	int count = 0;

	for (pipe = 0; pipe < port->pipes_mask + 1; pipe++) {
		count += dump_pipe_stats(port, sp, pipe);
	}

	return count;
}
#endif

void fpn_sw_sched_dump_stats(void *sw_port, char *tok)
{
	fpn_sw_sched_rte_port_t *port = sw_port;
#ifdef FPN_SW_SCHED_RTE_STATS
	uint32_t sp;
	int count = 0;
#endif

	(void) tok;

	fpn_printf("default_class=%lu\n", port->default_class);
	fpn_printf("invalid_class=%lu\n", port->invalid_class);

#ifdef FPN_SW_SCHED_RTE_STATS
	if (!strncmp(tok, "-v", 2)) {
		fpn_printf("|sp|      pipe|tc| q|    nb_pkts|    nb_drop|"
		           "      bytes|    dropped|       qlen|\n");

		/* subports_mask is max subport - 1 (see allocate function) */
		for (sp = 0; sp < port->subports_mask + 1; sp++) {
			count += dump_subport_stats(port, sp);
		}

		fpn_printf("count=%d\n", count);
	}
#endif
}

void fpn_sw_sched_reset_stats(void *sw_port, char *tok)
{
	fpn_sw_sched_rte_port_t *port = sw_port;

	(void) tok;
	port->default_class = 0;
	port->invalid_class = 0;
}

static void fpn_sw_sched_init(void) __attribute__((constructor));
void fpn_sw_sched_init(void)
{
	memset (sched_rte_port, 0, sizeof(sched_rte_port));
}
