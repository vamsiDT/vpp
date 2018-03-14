#include <plugins/dpdk/device/flow_table.h>
flowcount_t *  nodet[TABLESIZE][NETINT] ;
activelist_t * head_af;
activelist_t * tail_af;
flowcount_t *  head[NETINT] ;
flowcount_t *  previousnode;
flowcount_t *  tail;
int numflows;
u32 r_qtotal;
u32 nbl[NETINT];
u64 t[NETINT]= {0,0};
u64 old_t[NETINT];
f32 threshold[NETINT];
activelist_t * act;
activelist_t * head_act[NETINT];
activelist_t * tail_act[NETINT];
