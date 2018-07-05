#include <dpdk/device/fifo.h>
u64 t[NUMINT] = {0,0,0,0};
u64 old_t[NUMINT];

u32 fifoqueue[NUMINT] = {0,0,0,0};
u32 threshold[NUMINT] = {344064,344064,344064,344064};