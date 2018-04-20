
#include "fp-anti-ddos.h"

static int fp_anti_ddos_main_loop(__attribute__((unused)) void *arg) {
	int i = 0, j = 0;
	int pkt_count = 0;

#define CACHE_ENTITY_SIZE 64
	struct buffer_entity entities[CACHE_ENTITY_SIZE] = {{0}};

	unsigned lcore_id;
	uint64_t cur_tsc;

	const uint64_t cycles_interval = fpn_timer_cycles_resolution;
	uint64_t lcore_server_period_sc = fpn_get_clock_hz(); // 1s
	uint64_t ad_free_period_sc = fpn_get_clock_hz(); // 1s
	uint64_t flush_period_sc = fpn_get_clock_hz() * 10; // 10s
	uint64_t flush_udp_table_period_sc = fpn_get_clock_hz(); // 1s
	uint64_t flush_server_table_period_sc =  fpn_get_clock_hz();// 1s

#ifdef CONFIG_MCORE_DEBUG_CPU_USAGE
	cpu_usage_declare();
#endif

	ad_free_init();
	ring_buffer_init();
	ddos_loop_start();

	lcore_id = rte_lcore_id();

	/* main loop */
	for(;;) {

		FPN_ENTER(lcore_id);

		FP_CYCLES_TEST();

		sys_tsc = rte_rdtsc();

		cur_tsc = sys_tsc;

		cpu_usage(cur_tsc);

		for( i = 0; i < FPN_MAX_CORES; i ++) {
			if (!rte_lcore_is_enabled(i) || ring_buffer_empty(&ring_buffer[i])) {
				continue;
			}

			cpu_usage_acc();

			pkt_count = ring_buffer_dequeue(&ring_buffer[i], entities, CACHE_ENTITY_SIZE);
			for(j = 0; j < pkt_count; j ++) {
				struct buffer_entity* e = entities + j;
				switch (entry_type(e)) {
					case ENTRY_STRUCT_PK_INFO:
						process_info(entry_data(e, struct pkt_common_info*));
					break;
					case ENTRY_FLUSH_STATUS_FLOW_CACHE:
						flush_server_flow_info_cache(i);
					break;
					case ENTRY_FLUSH_CLIENT_UDP_INFO:
						flush_client_udp_info_cache(i);
					break;
					case ENTRY_FLUSH_SYN_CHECK_INFO:
						flush_syn_check_info_cache(i);
					break;
					default:
					break;
				}
			}
		}

		CYCLES_LIMIT_CODE(cur_tsc, lcore_server_period_sc, {
			flush_lcore_server(cur_tsc);

			for( i = 0; i < FPN_MAX_CORES; i ++) {
				if (!rte_lcore_is_enabled(i)) {
					continue;
				}
				flush_server_flow_info_cache(i);
				flush_client_udp_info_cache(i);
				flush_syn_check_info_cache(i);
			}

			cpu_usage_acc();
		})

		CYCLES_LIMIT_CODE(cur_tsc, flush_server_table_period_sc, {

			flush_server_table(cur_tsc, flush_server_table_period_sc);
			cpu_usage_acc();
		})

		CYCLES_LIMIT_CODE(cur_tsc, flush_period_sc, {
			flush_tcp_query_table(cur_tsc);
			flush_udp_query_table(cur_tsc);
			cpu_usage_acc();
		})

		CYCLES_LIMIT_CODE(cur_tsc, flush_udp_table_period_sc, {
			flush_client_tcp_table(cur_tsc);
			flush_client_udp_table(cur_tsc);
			cpu_usage_acc();
		})



		CYCLES_LIMIT_CODE(cur_tsc, ad_free_period_sc, {
			ad_free_check();
			cpu_usage_acc();
		})

		CYCLES_LIMIT_CODE(cur_tsc, cycles_interval, {
			cpu_usage_check(lcore_id, cur_tsc);
		})

		FPN_EXIT(lcore_id);
	}

	return 0;
}

FPN_DDOS_PROC_REGISTER(fp_anti_ddos_main_loop)