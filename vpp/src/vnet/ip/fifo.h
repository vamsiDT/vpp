#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#include <vnet/vnet.h>
#include <stdlib.h>
#include <math.h>
#ifndef FIFO_H
#define FIFO_H
#define ALPHA 0.3
extern u64 old_t;
extern u64 t;
extern u32 threshold;
extern u32 fifoqueue;

always_inline u8 fifo(u16 pktlen){
	u8 drop;
	if(fifoqueue <= threshold ){
		fifoqueue+=pktlen;
        drop=0;
    }
	else
		drop=1;
return drop;
}

#endif /*FIFO_H*/
