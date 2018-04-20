#ifndef _HAOROUTED_ZEBRA_H_
#define _HAOROUTED_ZEBRA_H_

void hao_routed_zebra_process_route(uint8_t command, void *p, void *api);
void hao_routed_zebra_redistribute();
void hao_routed_zebra_init();
int hao_routed_peer_zebra_restart();

#endif /* _HAOROUTED_ZEBRA_H_ */
