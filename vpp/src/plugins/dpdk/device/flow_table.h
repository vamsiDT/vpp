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
#define TABLESIZE 4096
#define ALPHA 1.0
#define BUFFER 384000 //just a random number. Update the value with proper theoritical approach.
#define NUMFLOWS 4096
#define THRESHOLD (19200) //just a random number. Update the value with proper theoritical approach.

/*Node in the flow table. srcdst is 64 bit divided as |32bitsrcip|32bitdstip| ; swsrcdstport is divided as |32bit swifindex|16bit srcport|16bit dstport|*/
typedef struct flowcount{
    u32 hash;
    u32 vqueue;
    struct flowcount * branchnext;
    struct flowcount * update;
}flowcount_t;

typedef struct activelist{
    struct flowcount * flow;
    struct activelist * next;
}activelist_t;

extern flowcount_t *  nodet[TABLESIZE];
extern activelist_t * head_af;
extern activelist_t * tail_af;
extern flowcount_t *  head ;
extern int numflows;
extern u32 r_qtotal;
extern u32 nbl;
extern u64 t;
extern u64 old_t;
extern f32 threshold;
extern activelist_t * act;
extern activelist_t * head_act;
extern activelist_t * tail_act;
extern struct rte_mbuf * f_vectors[VLIB_FRAME_SIZE];
extern u32 n_packets;

/* Flow classification function */
always_inline flowcount_t *
flow_table_classify(u32 modulox, u32 hashx0, u16 pktlenx){

    flowcount_t * flow;

    if (PREDICT_FALSE(head == NULL)){
        numflows = 0;
//        nbl = 0;
        nodet[modulox] = malloc(4*sizeof(flowcount_t));
        (nodet[modulox] + 0)->branchnext = NULL;
        (nodet[modulox] + 1)->branchnext = NULL;
        (nodet[modulox] + 2)->branchnext = NULL;
        (nodet[modulox] + 3)->branchnext = NULL;
        numflows++;
        (nodet[modulox] + 0)->hash = hashx0;
        (nodet[modulox] + 0)->update = (nodet[modulox] + 0);
        head = nodet[modulox] + 0;
        flow = nodet[modulox] + 0;
    }

    else if ( (nodet[modulox] + 0) == NULL ){
        nodet[modulox] = malloc(4*sizeof(flowcount_t));
        (nodet[modulox] + 0)->branchnext = NULL;
        (nodet[modulox] + 1)->branchnext = NULL;
        (nodet[modulox] + 2)->branchnext = NULL;
        (nodet[modulox] + 3)->branchnext = NULL;
        numflows++;
        (nodet[modulox] + 0)->hash = hashx0;
        (nodet[modulox] + 0)->update = (nodet[modulox] + 0);
        flow = nodet[modulox] + 0;
    }

    else if  ((nodet[modulox] + 0)->branchnext == NULL)
    {
        if  ( (nodet[modulox] + 0)->hash != hashx0 )
        {
            numflows++;
            (nodet[modulox] + 1)->hash = hashx0;
            (nodet[modulox] + 0)->branchnext = (nodet[modulox] + 1);
            flow = nodet[modulox] + 1;
        }
        else
        {
            flow = nodet[modulox] + 0;
        }
    }

    else if ( (nodet[modulox] + 1)->branchnext == NULL )
    {
        if ( (nodet[modulox] + 0)->hash != hashx0 ) {
            if ( (nodet[modulox] + 1)->hash != hashx0 ) {

                numflows++;
                (nodet[modulox] + 2)->hash = hashx0;
                (nodet[modulox] + 1)->branchnext = nodet[modulox] + 2;
                flow = nodet[modulox] + 2;
            }
            else
            {
                flow = nodet[modulox] + 1;
            }
        }
        else
        {
            flow = nodet[modulox] + 0;
        }
    }

    else if ( (nodet[modulox] + 2)->branchnext == NULL ){
        if ( (nodet[modulox] + 0)->hash != hashx0 ) {
            if ( (nodet[modulox] + 1)->hash != hashx0 ) {
                if ( (nodet[modulox] + 2)->hash != hashx0 ) {

                    numflows++;
                    (nodet[modulox] + 3)->hash = hashx0;
                    (nodet[modulox] + 2)->branchnext = nodet[modulox] + 3;
                    (nodet[modulox] + 3)->branchnext = nodet[modulox] + 0;
                    flow = nodet[modulox] + 3;
                }
                else
                {
                    flow = nodet[modulox] + 2;
                }
            }
            else
            {
                flow = nodet[modulox] + 1;
            }
        }
        else
        {
            flow = nodet[modulox] + 0;
        }
    }

    else
    {
        if ( (nodet[modulox] + 0)->hash != hashx0 ) {

            if ( (nodet[modulox] + 1)->hash != hashx0 ) {

                if ( (nodet[modulox] + 2)->hash != hashx0 ) {

                    if ( (nodet[modulox] + 3)->hash != hashx0 ) {

                        ((nodet[modulox] + 0)->update)->hash = hashx0;
						((nodet[modulox] + 0)->update)->vqueue=0;
                        flow = (nodet[modulox] + 0)->update;
                        (nodet[modulox] + 0)->update = ((nodet[modulox] + 0)->update)->branchnext ;
                    }
                    else
                    {
                        flow = nodet[modulox] + 3;
                    }
                }
                else
                {
                    flow = nodet[modulox] + 2;
                }
            }
            else
            {
                flow = nodet[modulox] + 1;
            }
        }
        else
        {
            flow = nodet[modulox] + 0;
        }
    }

    return flow;
}

/* function to insert the flow in blacklogged flows list. The flow is inserted at the end of the list i.e tail.*/

always_inline void flowin(flowcount_t * flow){
    activelist_t * temp;
    temp = malloc(sizeof(activelist_t));
    temp->flow = flow;
    temp->next = NULL;
    if (head_af == NULL){
        head_af = temp;
        tail_af = temp;
    }
    else{
        tail_af->next = temp;
        tail_af = temp;
    }
}

/* function to extract the flow from the blacklogged flows list. The flow is taken from the head of the list. */

always_inline flowcount_t * flowout(){
    flowcount_t * temp;
    activelist_t * next;
    temp = head_af->flow;
    next = head_af->next;
    free(head_af);
    head_af = next;
    return temp;
}

/*Ring Activelist Implementation with size NUMFLOWS.
**Activelist entries are overwritten when the activelist is full. (Algorithm cannot work when the activelist overflows)
  */

always_inline void activelist_init(){
    act = malloc(NUMFLOWS*sizeof(activelist_t));
    for(int j=0;j<(NUMFLOWS-1);j++){
        (act+j)->flow=NULL;
        (act+j)->next=(act+j+1);
    }
    (act+(NUMFLOWS-1))->flow=NULL;
    (act+(NUMFLOWS-1))->next=(act+0);
    head_act=tail_act=(act+0);
}

always_inline void flowin_act(flowcount_t * flow){

	if(PREDICT_FALSE(head_act==tail_act->next)){
        head_act=head_act->next;
        tail_act=tail_act->next;
    }
	else if(head_act->flow!=NULL)
		tail_act=tail_act->next;
	    tail_act->flow=flow;

}

always_inline flowcount_t * flowout_act(){

	flowcount_t * i = head_act->flow;
    head_act->flow=NULL;
     if(tail_act!=head_act){
        head_act=head_act->next;
     }
    return i;
}

/* vstate algorithm */
always_inline void vstate(flowcount_t * flow, u16 pktlenx,u8 update){

    if(PREDICT_FALSE(update == 1)){
        flowcount_t * j;
        u32 served,credit;
        int oldnbl=nbl+1;
        credit=(t-old_t)*ALPHA*10;
//		threshold = (credit)/nbl;
        while (oldnbl>nbl && nbl > 0 ){
            oldnbl = nbl;
            served = credit/nbl;
            credit = 0;
            for (int k=0;k<oldnbl;k++){
                j = flowout_act();
                if(j->vqueue > served){
                    j->vqueue -= served;
                    flowin_act(j);
                }
                else{
                    credit += served - j->vqueue;
                    j->vqueue = 0;
                    nbl--;
                }
            }
        }
    }

    if (flow != NULL){
        if (flow->vqueue == 0){
			if(nbl<NUMFLOWS)
            nbl++;
            flowin_act(flow);
        }
        flow->vqueue += pktlenx;
    }
}

/* arrival function for each packet */
always_inline u8 arrival(struct rte_mbuf * mb,u16 j,flowcount_t * flow,u16 pktlenx){
    if(flow->vqueue <= threshold){
        vstate(flow,pktlenx,0);
        f_vectors[j]=mb;
        return 1;
    }
    else {
        rte_pktmbuf_free(mb);
        return 0;
    }
}

/*vstate update function before sending the vector. This function is after processing all the packets in the vector and runs only once per vector */
always_inline void departure (){
    vstate(NULL,0,1);
}

/*
  Function to create a sub vector of packets which are accepted by fairdrop algiorithm
*/

always_inline u32 fairdrop_vectors (dpdk_device_t *xd,u16 queue_id, u32 n_buffers, u32 cpu_index){
  u32 n_buf = n_buffers;
  u16 i=0;
  u16 j=0;

  while(n_buf>0){
    u32 hash0,hash1,hash2,hash3;
    u32 hash4,hash5,hash6,hash7;
    u16 pktlen0,pktlen1,pktlen2,pktlen3;
    u16 pktlen4,pktlen5,pktlen6,pktlen7;
    u8 modulo0,modulo1,modulo2,modulo3;
    u8 modulo4,modulo5,modulo6,modulo7;
    struct rte_mbuf *mb0,*mb1,*mb2,*mb3;
    struct rte_mbuf *mb4,*mb5,*mb6,*mb7;
    flowcount_t * i0,*i1,*i2,*i3;
    flowcount_t * i4,*i5,*i6,*i7;

    while(n_buf>=8){

      mb0 = xd->rx_vectors[queue_id][i];
      mb1 = xd->rx_vectors[queue_id][i+1];
      mb2 = xd->rx_vectors[queue_id][i+2];
      mb3 = xd->rx_vectors[queue_id][i+3];
      mb4 = xd->rx_vectors[queue_id][i+4];
      mb5 = xd->rx_vectors[queue_id][i+5];
      mb6 = xd->rx_vectors[queue_id][i+6];
      mb7 = xd->rx_vectors[queue_id][i+7];

      hash0 = mb0->hash.rss;
      hash1 = mb1->hash.rss;
      hash2 = mb2->hash.rss;
      hash3 = mb3->hash.rss;
      hash4 = mb4->hash.rss;
      hash5 = mb5->hash.rss;
      hash6 = mb6->hash.rss;
      hash7 = mb7->hash.rss;

      pktlen0 = (mb0->pkt_len + 4)*8;
      pktlen1 = (mb1->pkt_len + 4)*8;
      pktlen2 = (mb2->pkt_len + 4)*8;
      pktlen3 = (mb3->pkt_len + 4)*8;
      pktlen4 = (mb4->pkt_len + 4)*8;
      pktlen5 = (mb5->pkt_len + 4)*8;
      pktlen6 = (mb6->pkt_len + 4)*8;
      pktlen7 = (mb7->pkt_len + 4)*8;

      modulo0 = hash0%TABLESIZE;
      modulo1 = hash1%TABLESIZE;
      modulo2 = hash2%TABLESIZE;
      modulo3 = hash3%TABLESIZE;
      modulo4 = hash4%TABLESIZE;
      modulo5 = hash5%TABLESIZE;
      modulo6 = hash6%TABLESIZE;
      modulo7 = hash7%TABLESIZE;


      i0 = flow_table_classify(modulo0, hash0, pktlen0);
      i1 = flow_table_classify(modulo1, hash1, pktlen1);
      i2 = flow_table_classify(modulo2, hash2, pktlen2);
      i3 = flow_table_classify(modulo3, hash3, pktlen3);
      i4 = flow_table_classify(modulo4, hash4, pktlen4);
      i5 = flow_table_classify(modulo5, hash5, pktlen5);
      i6 = flow_table_classify(modulo6, hash6, pktlen6);
      i7 = flow_table_classify(modulo7, hash7, pktlen7);

      j += arrival(mb0,j,i0,pktlen0);
      j += arrival(mb1,j,i1,pktlen1);
      j += arrival(mb2,j,i2,pktlen2);
      j += arrival(mb3,j,i3,pktlen3);
      j += arrival(mb4,j,i4,pktlen4);
      j += arrival(mb5,j,i5,pktlen5);
      j += arrival(mb6,j,i6,pktlen6);
      j += arrival(mb7,j,i7,pktlen7);

    i+=8;
    n_buf-=8;

  }
    while(n_buf>0){

      mb0 = xd->rx_vectors[queue_id][i];

      hash0 = mb0->hash.rss;

      pktlen0 = (mb0->pkt_len + 4)*8;

      modulo0 = hash0%TABLESIZE;

      i0 = flow_table_classify(modulo0, hash0, pktlen0);

      j += arrival(mb0,j,i0,pktlen0);

      i++;
      n_buf--;

    }
  }

  return j;
}

#endif /*FLOW_TABLE_H*/

/*
*   "Gather ye rosebuds while ye may"
*                  - Mike Portnoy
*
*   End
*
*/
