/*
*   Flow classification in VPP
*
*         flow_table.h
*
*
*
*/
#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#include <vnet/vnet.h>
#include <stdlib.h>
#include <math.h>
#include <plugins/dpdk/device/dpdk.h>
#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H
#define ALPHA 0.9
#define NUMINT 4


extern u64 t[NUMINT];
extern u64 old_t[NUMINT];

extern u32 threshold[NUMINT];
extern u32 fifoqueue[NUMINT];

always_inline u8 fifo(u16 pktlen,u32 device_index){
	u8 drop;
	if(fifoqueue[device_index] < threshold[device_index] ){
		fifoqueue[device_index]+=pktlen;
        drop=0;
    }
	else
		drop=1;
return drop;
}


static_always_inline u32
taildrop_enqueue (struct rte_mbuf **pkts, struct rte_mbuf **fd_pkts, uint32_t n_pkts, u32 device_index)
{
  u32 n_buffers=n_pkts;
  u32 mb_index=0;
  u32 fd_index=0;

  while (n_buffers > 0)
    {
//////////////////////////////////////////////
    u16 pktlen0,pktlen1,pktlen2,pktlen3;
    u8  drop0,drop1,drop2,drop3;
    old_t[device_index] = t[device_index];
    t[device_index] = (u64)(unix_time_now_nsec());
    threshold[device_index]=(t[device_index]-old_t[device_index])*10*ALPHA;
//////////////////////////////////////////////

      while (n_buffers >= 12)
    {
      struct rte_mbuf *mb0, *mb1, *mb2, *mb3;

      /* prefetches are interleaved with the rest of the code to reduce
         pressure on L1 cache */
      // dpdk_prefetch_buffer (pkts[mb_index + 8]);
      // dpdk_prefetch_ethertype (pkts[mb_index + 4]);

      mb0 = pkts[mb_index];
      mb1 = pkts[mb_index + 1];
      mb2 = pkts[mb_index + 2];
      mb3 = pkts[mb_index + 3];

      ASSERT (mb0);
      ASSERT (mb1);
      ASSERT (mb2);
      ASSERT (mb3);


      // dpdk_prefetch_buffer (pkts[mb_index + 9]);
      // dpdk_prefetch_ethertype (pkts[mb_index + 5]);

      // dpdk_prefetch_buffer (pkts[mb_index + 10]);
      // dpdk_prefetch_ethertype (pkts[mb_index + 7]);

      // dpdk_prefetch_buffer (pkts[mb_index + 11]);
      // dpdk_prefetch_ethertype (pkts[mb_index + 6]);


    pktlen0 = (mb0->data_len + 24)*8;
    pktlen1 = (mb1->data_len + 24)*8;
    pktlen2 = (mb2->data_len + 24)*8;
    pktlen3 = (mb3->data_len + 24)*8;

    drop0 = fifo(pktlen0,device_index);
    drop1 = fifo(pktlen1,device_index);
    drop2 = fifo(pktlen2,device_index);
    drop3 = fifo(pktlen3,device_index);
//	drop0=0;
//	drop1=0;
//	drop2=0;
//	drop3=0;

    if(PREDICT_FALSE(drop0 == 1)){
        rte_pktmbuf_free(mb0);
    }
    else{
        fd_pkts[fd_index]=mb0;
        fd_index++;
    }
    if(PREDICT_FALSE(drop1 == 1)){
        rte_pktmbuf_free(mb1);
    }
    else{
        fd_pkts[fd_index]=mb1;
        fd_index++;
    }
    if(PREDICT_FALSE(drop2 == 1)){
        rte_pktmbuf_free(mb2);
    }
    else{
        fd_pkts[fd_index]=mb2;
        fd_index++;
    }
    if(PREDICT_FALSE(drop3 == 1)){
        rte_pktmbuf_free(mb3);
    }
    else{
        fd_pkts[fd_index]=mb3;
        fd_index++;
    }

      n_buffers -= 4;
      mb_index += 4;
    }

      while (n_buffers > 0 )
    {
      struct rte_mbuf *mb0 = pkts[mb_index];

      // if (PREDICT_TRUE (n_buffers > 3))
      //   {
      //     dpdk_prefetch_buffer (pkts[mb_index + 2]);
      //     dpdk_prefetch_ethertype (pkts
      //                  [mb_index + 1]);
      //   }

      ASSERT (mb0);

////////////////////////////////////////////////

    pktlen0 = (mb0->data_len + 24)*8;

    drop0 = fifo(pktlen0,device_index);
//	drop0 = 0;

    if(PREDICT_FALSE(drop0 == 1)){
        rte_pktmbuf_free(mb0);
    }
    else{
        fd_pkts[fd_index]=mb0;
        fd_index++;
    }
////////////////////////////////////////////////

      n_buffers--;
      mb_index++;
    }

    }

  return fd_index;
}



#endif /*FLOW_TABLE_H*/

/*
*   "Gather ye rosebuds while ye may"
*                  - Mike Portnoy
*
*   End
*
*/

