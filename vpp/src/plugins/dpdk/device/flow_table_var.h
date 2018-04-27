#include <dpdk/device/flow_table.h>
flowcount_t *  nodet[TABLESIZE][NUMINT] ;
activelist_t * head_af;
activelist_t * tail_af;
flowcount_t *  head[NUMINT] ;
flowcount_t *  previousnode;
flowcount_t *  tail;
int numflows;
u32 r_qtotal;
u32 nbl[NUMINT];
u64 t[NUMINT] = {0,0,0,0};
u64 old_t[NUMINT];
f32 threshold;
activelist_t * act;
activelist_t * head_act[NUMINT];
activelist_t * tail_act[NUMINT];
