#include <plugins/dpdk/device/flow_table_cpu.h>
flowcount_t *  nodet[TABLESIZE][MAXCPU] ;
activelist_t * head_af[MAXCPU];
activelist_t * tail_af[MAXCPU];
flowcount_t *  head[MAXCPU] ;
flowcount_t *  previousnode;
flowcount_t *  tail[MAXCPU];
u32 nbl[MAXCPU]= {0,0,0,0};
u64 t[MAXCPU] = {0,0,0,0};
u64 old_t[MAXCPU];
u8 hello_world[MAXCPU] = {0,0,0,0};
f64 s[MAXCPU] = {0,0,0,0};
f64 s_total[MAXCPU] = {0,0,0,0};
u32 busyloop[MAXCPU]={0,0,0,0};
u32 veryold_t[MAXCPU]={0,0,0,0};
f64 sum[MAXCPU]={0,0,0,0};
f64 dpdk_cost_total[MAXCPU]={0,0,0,0};

f32 threshold[MAXCPU]={THRESHOLD,THRESHOLD,THRESHOLD,THRESHOLD};
struct rte_mbuf * f_vectors[VLIB_FRAME_SIZE];
activelist_t * act;
activelist_t * head_act[MAXCPU];
activelist_t * tail_act[MAXCPU];
u32 n_pack[MAXCPU]={1,1,1,1};
