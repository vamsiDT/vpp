#include <plugins/dpdk/device/flow_table_cpu.h>
flowcount_t *  nodet[TABLESIZE][MAXCPU] ;
activelist_t * head_af[MAXCPU];
activelist_t * tail_af[MAXCPU];
flowcount_t *  head[MAXCPU] ;
flowcount_t *  previousnode;
flowcount_t *  tail[MAXCPU];
u32 r_qtotal;
u32 nbl[MAXCPU];
u64 t[MAXCPU] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
u64 old_t[MAXCPU];
u8 hello_world[MAXCPU] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
u64 s[MAXCPU] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
u64 s_total[MAXCPU] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
u8 n_drops[MAXCPU] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
u32 flows[MAXCPU]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
