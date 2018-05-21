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
#define ALPHA 0.1
#define BUFFER 384000 //just a random number. Update the value with proper theoritical approach.
#define THRESHOLD (262144) //(19200*3) //just a random number. Update the value with proper theoritical approach.
//#define THRESHOLD 4096
#define NUMFLOWS 10240
#define NUMINT 4

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

extern flowcount_t *  nodet[TABLESIZE][NUMINT];
extern activelist_t * head_af;
extern activelist_t * tail_af;
extern flowcount_t *  head[NUMINT] ;
extern int numflows;
extern u32 r_qtotal;
extern u32 nbl[NUMINT];
extern u64 t[NUMINT];
extern u64 old_t[NUMINT];
extern f32 threshold;
extern activelist_t * act;
extern activelist_t * head_act[NUMINT];
extern activelist_t * tail_act[NUMINT];

/* Flow classification function */
always_inline flowcount_t *
flow_table_classify(u32 modulox, u32 hashx0, u16 pktlenx,u32 device_index) {
    flowcount_t * flow;

    if (PREDICT_FALSE(head[device_index] == NULL)){
        numflows = 0;
        nbl[device_index] = 0;
        nodet[modulox][device_index] = malloc(4*sizeof(flowcount_t));
        (nodet[modulox][device_index] + 0)->branchnext = NULL;
        (nodet[modulox][device_index] + 1)->branchnext = NULL;
        (nodet[modulox][device_index] + 2)->branchnext = NULL;
        (nodet[modulox][device_index] + 3)->branchnext = NULL;
        (nodet[modulox][device_index] + 0)->hash = hashx0;
        (nodet[modulox][device_index] + 0)->update = (nodet[modulox][device_index] + 0);
        head[device_index] = nodet[modulox][device_index] + 0;
        flow = nodet[modulox][device_index] + 0;
    }

    else if ( (nodet[modulox][device_index] + 0) == NULL ){
        nodet[modulox][device_index] = malloc(4*sizeof(flowcount_t));
        (nodet[modulox][device_index] + 0)->branchnext = NULL;
        (nodet[modulox][device_index] + 1)->branchnext = NULL;
        (nodet[modulox][device_index] + 2)->branchnext = NULL;
        (nodet[modulox][device_index] + 3)->branchnext = NULL;
        numflows++;
        (nodet[modulox][device_index] + 0)->hash = hashx0;
        (nodet[modulox][device_index] + 0)->update = (nodet[modulox][device_index] + 0);
        flow = nodet[modulox][device_index] + 0;
    }

    else if  ((nodet[modulox][device_index] + 0)->branchnext == NULL)
    {
        if  ( (nodet[modulox][device_index] + 0)->hash != hashx0 )
        {
            (nodet[modulox][device_index] + 1)->hash = hashx0;
            (nodet[modulox][device_index] + 0)->branchnext = (nodet[modulox][device_index] + 1);
            flow = nodet[modulox][device_index] + 1;
        }
        else
        {
            flow = nodet[modulox][device_index] + 0;
        }
    }

    else if ( (nodet[modulox][device_index] + 1)->branchnext == NULL )
    {
        if ( (nodet[modulox][device_index] + 0)->hash != hashx0 ) {
            if ( (nodet[modulox][device_index] + 1)->hash != hashx0 ) {

                (nodet[modulox][device_index] + 2)->hash = hashx0;
                (nodet[modulox][device_index] + 1)->branchnext = nodet[modulox][device_index] + 2;
                flow = nodet[modulox][device_index] + 2;
            }
            else
            {
                flow = nodet[modulox][device_index] + 1;
            }
        }
        else
        {
            flow = nodet[modulox][device_index] + 0;
        }
    }

    else if ( (nodet[modulox][device_index] + 2)->branchnext == NULL ){
        if ( (nodet[modulox][device_index] + 0)->hash != hashx0 ) {
            if ( (nodet[modulox][device_index] + 1)->hash != hashx0 ) {
                if ( (nodet[modulox][device_index] + 2)->hash != hashx0 ) {

                    (nodet[modulox][device_index] + 3)->hash = hashx0;
                    (nodet[modulox][device_index] + 2)->branchnext = nodet[modulox][device_index] + 3;
                    (nodet[modulox][device_index] + 3)->branchnext = nodet[modulox][device_index] + 0;
                    flow = nodet[modulox][device_index] + 3;
                }
                else
                {
                    flow = nodet[modulox][device_index] + 2;
                }
            }
            else
            {
                flow = nodet[modulox][device_index] + 1;
            }
        }
        else
        {
            flow = nodet[modulox][device_index] + 0;
        }
    }

    else
    {
        if ( (nodet[modulox][device_index] + 0)->hash != hashx0 ) {

            if ( (nodet[modulox][device_index] + 1)->hash != hashx0 ) {

                if ( (nodet[modulox][device_index] + 2)->hash != hashx0 ) {

                    if ( (nodet[modulox][device_index] + 3)->hash != hashx0 ) {

                        ((nodet[modulox][device_index] + 0)->update)->hash = hashx0;
                        flow = (nodet[modulox][device_index] + 0)->update;
                        (nodet[modulox][device_index] + 0)->update = ((nodet[modulox][device_index] + 0)->update)->branchnext ;
                    }
                    else
                    {
                        flow = nodet[modulox][device_index] + 3;
                    }
                }
                else
                {
                    flow = nodet[modulox][device_index] + 2;
                }
            }
            else
            {
                flow = nodet[modulox][device_index] + 1;
            }
        }
        else
        {
            flow = nodet[modulox][device_index] + 0;
        }
    }

    return flow;
}

/* function to insert the flow in blacklogged flows list. The flow is inserted at the end of the list i.e tail.*/
/*
void flowin(flowcount_t * flow){
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
*/
/* function to extract the flow from the blacklogged flows list. The flow is taken from the head of the list. */
/*
flowcount_t * flowout(){
    flowcount_t * temp;
    activelist_t * next;
    temp = head_af->flow;
    next = head_af->next;
    free(head_af);
    head_af = next;
    return temp;
}
*/
always_inline void activelist_init(){
    act = malloc(NUMFLOWS*NUMINT*sizeof(activelist_t));
    for(int k=0;k<NUMINT;k++){
    for(int j=0;j<(NUMFLOWS-1);j++){
        (act+k*NUMFLOWS+j)->flow=NULL;
        (act+k*NUMFLOWS+j)->next=(act+k*NUMFLOWS+j+1);
    }
    (act+k*NUMFLOWS+(NUMFLOWS-1))->flow=NULL;
    (act+k*NUMFLOWS+(NUMFLOWS-1))->next=(act+k*NUMFLOWS+0);
    head_act[k]=tail_act[k]=(act+k*NUMFLOWS+0);
    }
}

always_inline void flowin_act(flowcount_t * flow,u32 device_index){

    if(PREDICT_FALSE(head_act[device_index]==tail_act[device_index]->next)){
        head_act[device_index]=head_act[device_index]->next;
        tail_act[device_index]=tail_act[device_index]->next;
    }
    else if(head_act[device_index]->flow!=NULL)
        tail_act[device_index]=tail_act[device_index]->next;
        tail_act[device_index]->flow=flow;

}

always_inline flowcount_t * flowout_act(u32 device_index){

    flowcount_t * i = head_act[device_index]->flow;
    head_act[device_index]->flow=NULL;
     if(tail_act[device_index]!=head_act[device_index]){
        head_act[device_index]=head_act[device_index]->next;
     }
    return i;
}

/* vstate algorithm */
always_inline void vstate(flowcount_t * flow, u16 pktlenx,u8 update,u32 device_index){

    if(PREDICT_FALSE(update == 1)){
        flowcount_t * j;
        f32 served,credit;
        int oldnbl=nbl[device_index]+1;
        credit = (t[device_index] - old_t[device_index])*10*ALPHA;
		//printf("nbl[%u]=%u\n",cpu_index,nbl[cpu_index]);
//		threshold = 153600;//credit/nbl;
        while (oldnbl>nbl[device_index] && nbl[device_index] > 0){
            oldnbl = nbl[device_index];
            served = credit/nbl[device_index];
            credit = 0;
            for (int k=0;k<oldnbl;k++){
                j = flowout_act(device_index);
                if(j->vqueue > served){
                    j->vqueue -= served;
                    flowin_act(j,device_index);
                }
                else{
                    credit += served - j->vqueue;
                    j->vqueue = 0;
                    nbl[device_index]--;
                }
            }
        }
    }

    if (flow != NULL){
        if (flow->vqueue == 0){
			if(nbl[device_index]<NUMFLOWS)
            nbl[device_index]++;
            flowin_act(flow,device_index);
        }
        flow->vqueue += pktlenx;
    }
}

/* arrival function for each packet */
always_inline u8 arrival(flowcount_t * flow, u16 pktlenx,u32 device_index){
u8 drop;
    if(flow->vqueue <= THRESHOLD){
        vstate(flow,pktlenx,0,device_index);
        drop = 0;
    }
    else {
        drop = 1;
        //update vstate is only after a vector. So no update before dropping a packet here.
    }
//drop = 0;
return drop;
}

always_inline u8 fq (u32 modulox, u32 hashx0, u16 pktlenx,u32 device_index){
    flowcount_t * i;
    u8 drop;
    i = flow_table_classify(modulox,hashx0,pktlenx,device_index);
    drop = arrival(i,pktlenx,device_index);
    return drop;
}

/*vstate update function before sending the vector. This function is after processing all the packets in the vector and runs only once per vector */
always_inline void departure (u32 device_index){
    vstate(NULL,0,1,device_index);
}


static_always_inline u32
fairdrop_enqueue (struct rte_mbuf **pkts, struct rte_mbuf **fd_pkts, uint32_t n_pkts, u32 device_index)
{
  u32 n_buffers=n_pkts;
  u32 mb_index=0;
  u32 fd_index=0;

  while (n_buffers > 0)
    {
//////////////////////////////////////////////
    u32 hash0,hash1,hash2,hash3;
    u32 modulo0,modulo1,modulo2,modulo3;
    u16 pktlen0,pktlen1,pktlen2,pktlen3;
    u8  drop0,drop1,drop2,drop3 ;
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

    hash0 = mb0->hash.rss;
    //printf("hash0=%u\n",hash0);
    hash1 = mb1->hash.rss;
    hash2 = mb2->hash.rss;
    hash3 = mb3->hash.rss;

    modulo0 = (hash0)%TABLESIZE;
    modulo1 = (hash1)%TABLESIZE;
    modulo2 = (hash2)%TABLESIZE;
    modulo3 = (hash3)%TABLESIZE;

    pktlen0 = (mb0->data_len + 24)*8;
    pktlen1 = (mb1->data_len + 24)*8;
    pktlen2 = (mb2->data_len + 24)*8;
    pktlen3 = (mb3->data_len + 24)*8;

    drop0 = fq(modulo0,hash0,pktlen0,device_index);
    drop1 = fq(modulo1,hash1,pktlen1,device_index);
    drop2 = fq(modulo2,hash2,pktlen2,device_index);
    drop3 = fq(modulo3,hash3,pktlen3,device_index);
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
    hash0 = mb0->hash.rss;

    modulo0 = (hash0)%TABLESIZE;

    pktlen0 = (mb0->data_len + 24)*8;

    drop0 = fq(modulo0,hash0,pktlen0,device_index);
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

/*vstate update*/
old_t[device_index] = t[device_index];
t[device_index] = (u64)(unix_time_now_nsec ());
departure(device_index);

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

