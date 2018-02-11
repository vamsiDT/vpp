#include <plugins/dpdk/device/flow_table.h>
flowcount_t *  nodet[TABLESIZE] ;
activelist_t * head_af;
activelist_t * tail_af;
flowcount_t *  head ;
flowcount_t *  previousnode;
flowcount_t *  tail;
int numflows;
u32 r_qtotal;
u32 nbl;
u64 t=0;
u64 old_t;
f32 threshold=19200;
activelist_t * act;
activelist_t * head_act;
activelist_t * tail_act;
struct rte_mbuf * f_vectors[VLIB_FRAME_SIZE];
u32 n_packets=512;
//f32 credit;
