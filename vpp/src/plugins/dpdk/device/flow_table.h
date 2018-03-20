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
#define THRESHOLD (19200*3) //just a random number. Update the value with proper theoritical approach.
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
flow_table_classify(u32 modulox, u32 hashx0, u16 pktlenx,u32 cpu_index) {
    flowcount_t * flow;

    if (PREDICT_FALSE(head[cpu_index] == NULL)){
        numflows = 0;
        nbl[cpu_index] = 0;
        nodet[modulox][cpu_index] = malloc(4*sizeof(flowcount_t));
        (nodet[modulox][cpu_index] + 0)->branchnext = NULL;
        (nodet[modulox][cpu_index] + 1)->branchnext = NULL;
        (nodet[modulox][cpu_index] + 2)->branchnext = NULL;
        (nodet[modulox][cpu_index] + 3)->branchnext = NULL;
        (nodet[modulox][cpu_index] + 0)->hash = hashx0;
        (nodet[modulox][cpu_index] + 0)->update = (nodet[modulox][cpu_index] + 0);
        head[cpu_index] = nodet[modulox][cpu_index] + 0;
        flow = nodet[modulox][cpu_index] + 0;
    }

    else if ( (nodet[modulox][cpu_index] + 0) == NULL ){
        nodet[modulox][cpu_index] = malloc(4*sizeof(flowcount_t));
        (nodet[modulox][cpu_index] + 0)->branchnext = NULL;
        (nodet[modulox][cpu_index] + 1)->branchnext = NULL;
        (nodet[modulox][cpu_index] + 2)->branchnext = NULL;
        (nodet[modulox][cpu_index] + 3)->branchnext = NULL;
        numflows++;
        (nodet[modulox][cpu_index] + 0)->hash = hashx0;
        (nodet[modulox][cpu_index] + 0)->update = (nodet[modulox][cpu_index] + 0);
        flow = nodet[modulox][cpu_index] + 0;
    }

    else if  ((nodet[modulox][cpu_index] + 0)->branchnext == NULL)
    {
        if  ( (nodet[modulox][cpu_index] + 0)->hash != hashx0 )
        {
            (nodet[modulox][cpu_index] + 1)->hash = hashx0;
            (nodet[modulox][cpu_index] + 0)->branchnext = (nodet[modulox][cpu_index] + 1);
            flow = nodet[modulox][cpu_index] + 1;
        }
        else
        {
            flow = nodet[modulox][cpu_index] + 0;
        }
    }

    else if ( (nodet[modulox][cpu_index] + 1)->branchnext == NULL )
    {
        if ( (nodet[modulox][cpu_index] + 0)->hash != hashx0 ) {
            if ( (nodet[modulox][cpu_index] + 1)->hash != hashx0 ) {

                (nodet[modulox][cpu_index] + 2)->hash = hashx0;
                (nodet[modulox][cpu_index] + 1)->branchnext = nodet[modulox][cpu_index] + 2;
                flow = nodet[modulox][cpu_index] + 2;
            }
            else
            {
                flow = nodet[modulox][cpu_index] + 1;
            }
        }
        else
        {
            flow = nodet[modulox][cpu_index] + 0;
        }
    }

    else if ( (nodet[modulox][cpu_index] + 2)->branchnext == NULL ){
        if ( (nodet[modulox][cpu_index] + 0)->hash != hashx0 ) {
            if ( (nodet[modulox][cpu_index] + 1)->hash != hashx0 ) {
                if ( (nodet[modulox][cpu_index] + 2)->hash != hashx0 ) {

                    (nodet[modulox][cpu_index] + 3)->hash = hashx0;
                    (nodet[modulox][cpu_index] + 2)->branchnext = nodet[modulox][cpu_index] + 3;
                    (nodet[modulox][cpu_index] + 3)->branchnext = nodet[modulox][cpu_index] + 0;
                    flow = nodet[modulox][cpu_index] + 3;
                }
                else
                {
                    flow = nodet[modulox][cpu_index] + 2;
                }
            }
            else
            {
                flow = nodet[modulox][cpu_index] + 1;
            }
        }
        else
        {
            flow = nodet[modulox][cpu_index] + 0;
        }
    }

    else
    {
        if ( (nodet[modulox][cpu_index] + 0)->hash != hashx0 ) {

            if ( (nodet[modulox][cpu_index] + 1)->hash != hashx0 ) {

                if ( (nodet[modulox][cpu_index] + 2)->hash != hashx0 ) {

                    if ( (nodet[modulox][cpu_index] + 3)->hash != hashx0 ) {

                        ((nodet[modulox][cpu_index] + 0)->update)->hash = hashx0;
                        flow = (nodet[modulox][cpu_index] + 0)->update;
                        (nodet[modulox][cpu_index] + 0)->update = ((nodet[modulox][cpu_index] + 0)->update)->branchnext ;
                    }
                    else
                    {
                        flow = nodet[modulox][cpu_index] + 3;
                    }
                }
                else
                {
                    flow = nodet[modulox][cpu_index] + 2;
                }
            }
            else
            {
                flow = nodet[modulox][cpu_index] + 1;
            }
        }
        else
        {
            flow = nodet[modulox][cpu_index] + 0;
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

always_inline void flowin_act(flowcount_t * flow,u32 cpu_index){

    if(PREDICT_FALSE(head_act[cpu_index]==tail_act[cpu_index]->next)){
        head_act[cpu_index]=head_act[cpu_index]->next;
        tail_act[cpu_index]=tail_act[cpu_index]->next;
    }
    else if(head_act[cpu_index]->flow!=NULL)
        tail_act[cpu_index]=tail_act[cpu_index]->next;
        tail_act[cpu_index]->flow=flow;

}

always_inline flowcount_t * flowout_act(u32 cpu_index){

    flowcount_t * i = head_act[cpu_index]->flow;
    head_act[cpu_index]->flow=NULL;
     if(tail_act[cpu_index]!=head_act[cpu_index]){
        head_act[cpu_index]=head_act[cpu_index]->next;
     }
    return i;
}

/* vstate algorithm */
always_inline void vstate(flowcount_t * flow, u16 pktlenx,u8 update,u32 cpu_index){

    if(PREDICT_FALSE(update == 1)){
        flowcount_t * j;
        f32 served,credit;
        int oldnbl=nbl[cpu_index]+1;
        credit = (t[cpu_index] - old_t[cpu_index])*10*ALPHA;
		//printf("nbl[%u]=%u\n",cpu_index,nbl[cpu_index]);
//		threshold = 153600;//credit/nbl;
        while (oldnbl>nbl[cpu_index] && nbl[cpu_index] > 0){
            oldnbl = nbl[cpu_index];
            served = credit/nbl[cpu_index];
            credit = 0;
            for (int k=0;k<oldnbl;k++){
                j = flowout_act(cpu_index);
                if(j->vqueue > served){
                    j->vqueue -= served;
                    flowin_act(j,cpu_index);
                }
                else{
                    credit += served - j->vqueue;
                    j->vqueue = 0;
                    nbl[cpu_index]--;
                }
            }
        }
    }

    if (flow != NULL){
        if (flow->vqueue == 0){
			if(nbl[cpu_index]<NUMFLOWS)
            nbl[cpu_index]++;
            flowin_act(flow,cpu_index);
        }
        flow->vqueue += pktlenx;
    }
}

/* arrival function for each packet */
always_inline u8 arrival(flowcount_t * flow, u16 pktlenx,u32 cpu_index){
u8 drop;
    if(flow->vqueue <= THRESHOLD){
        vstate(flow,pktlenx,0,cpu_index);
        drop = 0;
    }
    else {
        drop = 1;
        //update vstate is only after a vector. So no update before dropping a packet here.
    }
return drop;
}

always_inline u8 fq (u32 modulox, u32 hashx0, u16 pktlenx,u32 cpu_index){
    flowcount_t * i;
    u8 drop;
    i = flow_table_classify(modulox,hashx0,pktlenx,cpu_index);
    drop = arrival(i,pktlenx,cpu_index);
    return drop;
}

/*vstate update function before sending the vector. This function is after processing all the packets in the vector and runs only once per vector */
always_inline void departure (u32 cpu_index){
    vstate(NULL,0,1,cpu_index);
}
#endif /*FLOW_TABLE_H*/

/*
*   "Gather ye rosebuds while ye may"
*                  - Mike Portnoy
*
*   End
*
*/

