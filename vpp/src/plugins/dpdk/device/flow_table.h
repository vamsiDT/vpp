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
#define THRESHOLD (19200)
#define NUMFLOWS 10240

/* Hash table Flow entry */
typedef struct flowcount{
    u32 hash;
    u32 vqueue;
    struct flowcount * branchnext;
    struct flowcount * update;
}flowcount_t;

/* Activelist entry */
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

/* Flow classification function */
always_inline flowcount_t *
flow_table_classify(u32 modulox, u32 hashx0, u16 pktlenx){

    flowcount_t * flow;

    if (PREDICT_FALSE(head == NULL)){
        numflows = 0;
        nbl = 0;
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



/*
*               Functions related to activelist. 
* activelist_init --> creating a circular linked list for activelist
* flowin_act --> for adding a new entry to activelist at tail
* flowout_act --> for removing an entry from activelist at head
* update_costs --> for updating the costs of all the entries in the activelist
*/


/*Active list initialization at vpp startup. This function is called in dpdk_lib_init() */
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

/*Adding flow into the activelist*/
always_inline void flowin_act(flowcount_t * flow){

    if(PREDICT_FALSE(head_act==tail_act->next)){
        head_act=head_act->next;
        tail_act=tail_act->next;
    }
    else if(head_act->flow!=NULL)
        tail_act=tail_act->next;
        tail_act->flow=flow;

}

/*Removing flow from the activelist*/
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
        f32 served,credit;
        int oldnbl=nbl+1;
        credit = (t - old_t)*10*ALPHA;
        while (oldnbl>nbl && nbl > 0){
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
always_inline u8 arrival(flowcount_t * flow, u16 pktlenx){
u8 drop;
    if(flow->vqueue <= THRESHOLD){
        vstate(flow,pktlenx,0);
        drop = 0;
    }
    else {
        drop = 1;
    }
return drop;
}

/* Function for fairdrop algorithm, for each packet*/
always_inline u8 fairdrop (struct rte_mbuf *mb0){
    u32 hash0, modulo0;
    u16 pktlen0;
    flowcount_t * i;
    u8 drop;
    hash0 = mb0->hash.rss;
    modulo0 = (hash0)%TABLESIZE;
    pktlen0 = (mb0->data_len + 24)*8;
    i = flow_table_classify(modulo0,hash0,pktlen0);
    drop = arrival(i,pktlen0);
    return drop;
}

/*vstate update function before sending the vector. This function is after processing all the packets in the vector and called only once per vector */
always_inline void departure (){
    vstate(NULL,0,1);
}
#endif /*FLOW_TABLE_H*/

/*
*   CARPE DIEM
*   Sieze the day
*
*   The End
*
*/


