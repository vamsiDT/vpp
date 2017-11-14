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
#include <vppinfra/time.h>
#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H
#define TABLESIZE 4096
#define MAXCPU 24
#define ALPHACPU 0.97
#define THRESHOLD 1280000

#define WEIGHT_IP4	255
#define WEIGHT_IP6	510
#define WEIGHT_DROP 40
// typedef struct flowcount{
//     u32 n_packets;
//     u32 vqueue;
// }flowcount_t;

typedef struct flowcount{
    u32 hash;
    u32 vqueue;
    u16 weight;
    u16 cost;
    u32 n_packets;
    struct flowcount * branchnext;
    struct flowcount * update;
}flowcount_t;

typedef struct activelist{
    struct flowcount * flow;
    struct activelist * next;
}activelist_t;

extern flowcount_t *  nodet[TABLESIZE][MAXCPU];
extern activelist_t * head_af[MAXCPU];
extern activelist_t * tail_af[MAXCPU];
extern flowcount_t *  head [MAXCPU];
extern u32 r_qtotal;
extern u32 nbl[MAXCPU];
extern u64 t[MAXCPU];
extern u64 old_t[MAXCPU];
extern u8 hello_world[MAXCPU];
extern u64 s[MAXCPU];
extern u64 s_total[MAXCPU];
extern u8 n_drops[MAXCPU];

/* Flow/class classification function */
// always_inline flowcount_t *
// flow_table_classify(u8 modulox,u32 cpu_index){

//     flowcount_t * flow;

//     if(PREDICT_FALSE(nodet[modulox][cpu_index]==NULL)){
//         nodet[modulox][cpu_index] = malloc(sizeof(flowcount_t));
//         nodet[modulox][cpu_index]->vqueue=0;
//         nodet[modulox][cpu_index]->n_packets=0;
//     }
//         flow = nodet[modulox][cpu_index];

//     return flow;
// }

always_inline flowcount_t *
flow_table_classify(u32 modulox, u32 hashx0, u16 pktlenx, u32 cpu_index){

    flowcount_t * flow;

    if (PREDICT_FALSE(head[cpu_index] == NULL)){
        numflows = 0;
        nbl[cpu_index] = 0;
        nodet[modulox][cpu_index] = malloc(4*sizeof(flowcount_t));
        (nodet[modulox][cpu_index] + 0)->branchnext = NULL;
        (nodet[modulox][cpu_index] + 1)->branchnext = NULL;
        (nodet[modulox][cpu_index] + 2)->branchnext = NULL;
        (nodet[modulox][cpu_index] + 3)->branchnext = NULL;
        numflows++;
        (nodet[modulox][cpu_index] + 0)->hash = hashx0;
        (nodet[modulox][cpu_index] + 0)->weight = pktlenx;
        (nodet[modulox][cpu_index] + 0)->update = (nodet[modulox][cpu_index] + 0);
        head = nodet[modulox][cpu_index] + 0;
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
        (nodet[modulox][cpu_index] + 0)->weight = pktlenx;
        (nodet[modulox][cpu_index] + 0)->update = (nodet[modulox][cpu_index] + 0);
        flow = nodet[modulox][cpu_index] + 0;
    }

    else if  ((nodet[modulox][cpu_index] + 0)->branchnext == NULL)
    {
        if  ( (nodet[modulox][cpu_index] + 0)->hash != hashx0 )
        {
            numflows++;
            (nodet[modulox][cpu_index] + 1)->hash = hashx0;
            (nodet[modulox][cpu_index] + 1)->weight = pktlenx;
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

                numflows++;
                (nodet[modulox][cpu_index] + 2)->hash = hashx0;
                (nodet[modulox][cpu_index] + 2)->weight = pktlenx;
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

                    numflows++;
                    (nodet[modulox][cpu_index] + 3)->hash = hashx0;
                    (nodet[modulox][cpu_index] + 3)->weight = pktlenx;
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
                        ((nodet[modulox][cpu_index] + 0)->update)->weight = pktlenx;
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
void flowin(flowcount_t * flow,u32 cpu_index){
    activelist_t * temp;
    temp = malloc(sizeof(activelist_t));
    temp->flow = flow;
    temp->next = NULL;
    if (head_af[cpu_index] == NULL){
        head_af[cpu_index] = temp;
        tail_af[cpu_index] = temp;
    }
    else{
        tail_af[cpu_index]->next = temp;
        tail_af[cpu_index] = temp;
    }
}

/* function to extract the flow from the blacklogged flows list. The flow is taken from the head of the list. */
flowcount_t * flowout(u32 cpu_index){
    flowcount_t * temp;
    activelist_t * next;
    temp = head_af[cpu_index]->flow;
    next = head_af[cpu_index]->next;
    free(head_af[cpu_index]);
    head_af[cpu_index] = next;
    return temp;
}

/* vstate algorithm */
always_inline void vstate(flowcount_t * flow,u8 update,u32 cpu_index){

    if(PREDICT_FALSE(update == 1)){
        flowcount_t * j;
        f32 served,credit;
        int oldnbl=nbl[cpu_index]+1;
        credit = ((t[cpu_index]-old_t[cpu_index])*ALPHACPU);
        while (oldnbl>nbl[cpu_index] && nbl[cpu_index] > 0){
            oldnbl = nbl[cpu_index];
            served = credit/(nbl[cpu_index]);
            credit = 0;
            for (int k=0;k<oldnbl;k++){
                j = flowout(cpu_index);
                if(j->vqueue > served){
                    j->vqueue -= served;
                    flowin(j,cpu_index);
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
            nbl[cpu_index]++;
            flowin(flow,cpu_index);
			flow->vqueue = 1;
        }
		flow->n_packets++;
    }
}

/* arrival function for each packet */
always_inline u8 arrival(flowcount_t * flow,u32 cpu_index){
u8 drop;
    if(flow->vqueue <= THRESHOLD /*&& r_qtotal < BUFFER*/){
        vstate(flow,0,cpu_index);
        drop = 0;
    }
    else {
        drop = 1;
		n_drops[cpu_index]++;
    }
return drop;
}

always_inline u8 fq (u32 modulox, u32 hashx0, u16 pktlenx, u32 cpu_index){
    flowcount_t * i;
    u8 drop;
    i = flow_table_classify(modulox, hashx0, pktlenx, cpu_index);
    drop = arrival(i,cpu_index);
    return drop;
}

/*Function to update costs*/
always_inline void update_costs(vlib_main_t *vm,u32 cpu_index){
    activelist_t * costlist = head_af[cpu_index];
    f64 sum = 0;
    while (costlist != NULL){
        flowcount_t * flow = costlist->flow;
        sum += (flow->weight)*(flow->n_packets);
        costlist = costlist->next;
    }
    costlist = head_af[cpu_index];
    while(costlist != NULL){
        flowcount_t * flow = costlist->flow;
        flow->cost = ((f64)((flow->weight)*(s_total[index]-(n_drops[index]*WEIGHT_DROP))))/ sum;
        costlist = costlist->next;
    }
}

/*function to increment vqueues using the updated costs*/
always_inline void update_vstate(vlib_main_t * vm,u32 index){
    activelist_t * costlist = head_af[cpu_index];
    while(costlist != NULL){
        flowcount_t * flow = costlist->flow;
        flow->vqueue += (flow->n_packets)*(flow->cost);
        flow->n_packets = 0;
        costlist = costlist->next;
    }
}

always_inline void departure (u32 cpu_index){
    vstate(NULL,1,cpu_index);
}

always_inline void sleep_now (u64 t1,u64 old_t1){
	u64 t_sleep = ((t1-old_t1)*(1-ALPHACPU));
	clib_cpu_time_wait(t_sleep);
}


#endif /*FLOW_TABLE_H*/

/*
*   "Gather ye rosebuds while ye may"
*                  - Mike Portnoy
*
*   End
*
*/

