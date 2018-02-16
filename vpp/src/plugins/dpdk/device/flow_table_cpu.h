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
#include <plugins/dpdk/device/dpdk.h>
#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#define TABLESIZE 128
#define MAXCPU 4
#define ALPHACPU 1.0
#define NUMFLOWS 10240

//#define ELOG_FAIRDROP
//#define ELOG_DPDK_COST
#define BUSYLOOP
#define JIM_APPROX

#define WEIGHT_DROP 40

#ifdef ELOG_FAIRDROP
#define WEIGHT_DPDK 208
#else
#define WEIGHT_DPDK 158//185
#endif

#define WEIGHT_IP4E 192
#define WEIGHT_CLASS_1 350
#define WEIGHT_CLASS_2 (WEIGHT_DPDK+WEIGHT_IP4E)

#ifdef BUSYLOOP
#define FLOW_HASH_4157820474    (WEIGHT_CLASS_1)    //192.168.0.1
#define FLOW_HASH_2122681738    (WEIGHT_CLASS_1)	//192.168.0.3
#define FLOW_HASH_3010998242    (WEIGHT_CLASS_2)    //192.168.0.5
#define FLOW_HASH_976153682     (WEIGHT_CLASS_2)	//192.168.0.7
#define FLOW_HASH_1434910422    (WEIGHT_CLASS_2)    //192.168.0.9
#define FLOW_HASH_3704634726    (WEIGHT_CLASS_2)	//192.168.0.11
#define FLOW_HASH_288202510     (WEIGHT_CLASS_2)    //192.168.0.13
#define FLOW_HASH_2558221502    (WEIGHT_CLASS_2)    //192.168.0.15
#define FLOW_HASH_653891148     (WEIGHT_CLASS_2)    //192.168.0.17
#define FLOW_HASH_2947503612    (WEIGHT_CLASS_2)    //192.168.0.19
#define FLOW_HASH_1649604500    (WEIGHT_CLASS_2)	//192.168.0.21
#define FLOW_HASH_3942921252    (WEIGHT_CLASS_2)    //192.168.0.23
#define FLOW_HASH_2225874592    (WEIGHT_CLASS_2)    //192.168.0.25
#define FLOW_HASH_234546448     (WEIGHT_CLASS_2)    //192.168.0.27
#define FLOW_HASH_3221702520    (WEIGHT_CLASS_2)    //192.168.0.29
#define FLOW_HASH_1230079176    (WEIGHT_CLASS_2)    //192.168.0.31
#define FLOW_HASH_2381030752    (WEIGHT_CLASS_2)    //192.168.0.32
#define FLOW_HASH_79521488      (WEIGHT_CLASS_2)    //192.168.0.34
#define FLOW_HASH_3376465080    (WEIGHT_CLASS_2)    //192.168.0.36
#define FLOW_HASH_1075185416    (WEIGHT_CLASS_2)	//192.168.0.38
#endif

#define FLOW_HASH_DEFAULT       (WEIGHT_DPDK+WEIGHT_IP4E)

#ifdef BUSYLOOP
#define FLOW_COST(hash) (FLOW_HASH_##hash)
#else
#define FLOW_COST(hash) (FLOW_HASH_DEFAULT)
#endif

always_inline u16 flow_costvalue(u32 hash){
u16 cost;
	switch(hash){
		case 4157820474:
			cost = FLOW_COST(4157820474);
			break;
		case 2122681738:
            cost = FLOW_COST(2122681738);
            break;
        case 3010998242:
            cost = FLOW_COST(3010998242);
            break;
        case 976153682:
            cost = FLOW_COST(976153682);
            break;
        case 1434910422:
            cost = FLOW_COST(1434910422);
            break;
        case 3704634726:
            cost = FLOW_COST(3704634726);
            break;
        case 288202510:
            cost = FLOW_COST(288202510);
            break;
        case 2558221502:
            cost = FLOW_COST(2558221502);
            break;
        case 653891148:
            cost = FLOW_COST(653891148);
            break;
        case 2947503612:
            cost = FLOW_COST(2947503612);
            break;
        case 1649604500:
            cost = FLOW_COST(1649604500);
            break;
        case 3942921252:
            cost = FLOW_COST(3942921252);
            break;
        case 2225874592:
            cost = FLOW_COST(2225874592);
            break;
        case 234546448:
            cost = FLOW_COST(234546448);
            break;
        case 3221702520:
            cost = FLOW_COST(3221702520);
            break;
        case 1230079176:
            cost = FLOW_COST(1230079176);
            break;
        case 2381030752:
            cost = FLOW_COST(2381030752);
            break;
        case 79521488:
            cost = FLOW_COST(79521488);
            break;
        case 3376465080:
            cost = FLOW_COST(3376465080);
            break;
        case 1075185416:
            cost = FLOW_COST(1075185416);
            break;
		case 0:
			cost = FLOW_COST(DEFAULT);
        default:
            cost = FLOW_COST(DEFAULT);
	}
return cost;
}

typedef struct flowcount{
    u32 hash;
    u32 vqueue;
    u16 weight;
    u16 cost;
    struct flowcount * branchnext;
    struct flowcount * update;
}flowcount_t;

typedef struct activelist{
    struct flowcount * flow;
    struct activelist * next;
}activelist_t;

typedef struct cost_node{
	u64 clocks;
	u64 vectors;
}error_cost_t;

extern flowcount_t *  nodet[TABLESIZE][MAXCPU];
extern activelist_t * head_af[MAXCPU];
extern activelist_t * tail_af[MAXCPU];
extern flowcount_t *  head [MAXCPU];
extern u32 nbl[MAXCPU];
extern u64 t[MAXCPU];
extern u64 old_t[MAXCPU];
extern u32 veryold_t[MAXCPU];
extern u8 hello_world[MAXCPU];
extern u64 s[MAXCPU];
extern u64 s_total[MAXCPU];
extern u32 busyloop[MAXCPU];
extern f64 sum[MAXCPU];
extern u64 dpdk_cost_total[MAXCPU];

extern f32 threshold[MAXCPU];

extern activelist_t * act;
extern activelist_t * head_act[MAXCPU];
extern activelist_t * tail_act[MAXCPU];

//extern struct rte_mbuf * f_vectors[256];

always_inline flowcount_t *
flow_table_classify(u32 modulox, u32 hashx0, u16 pktlenx, u32 cpu_index){

    flowcount_t * flow;
    if (PREDICT_FALSE(head[cpu_index] == NULL)){
        nbl[cpu_index] = 0;
        nodet[modulox][cpu_index] = malloc(4*sizeof(flowcount_t));
        (nodet[modulox][cpu_index] + 0)->branchnext = NULL;
        (nodet[modulox][cpu_index] + 1)->branchnext = NULL;
        (nodet[modulox][cpu_index] + 2)->branchnext = NULL;
        (nodet[modulox][cpu_index] + 3)->branchnext = NULL;
        (nodet[modulox][cpu_index] + 0)->hash = hashx0;
        (nodet[modulox][cpu_index] + 0)->weight = pktlenx;
		(nodet[modulox][cpu_index] + 0)->cost = pktlenx;
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
        (nodet[modulox][cpu_index] + 0)->hash = hashx0;
        (nodet[modulox][cpu_index] + 0)->weight = pktlenx;
		(nodet[modulox][cpu_index] + 0)->cost = pktlenx;
        (nodet[modulox][cpu_index] + 0)->update = (nodet[modulox][cpu_index] + 0);
        flow = nodet[modulox][cpu_index] + 0;
    }

    else if  ((nodet[modulox][cpu_index] + 0)->branchnext == NULL)
    {
        if  ( (nodet[modulox][cpu_index] + 0)->hash != hashx0 )
        {
            (nodet[modulox][cpu_index] + 1)->hash = hashx0;
            (nodet[modulox][cpu_index] + 1)->weight = pktlenx;
			(nodet[modulox][cpu_index] + 1)->cost = pktlenx;
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
                (nodet[modulox][cpu_index] + 2)->weight = pktlenx;
				(nodet[modulox][cpu_index] + 2)->cost = pktlenx;
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
                    (nodet[modulox][cpu_index] + 3)->weight = pktlenx;
					(nodet[modulox][cpu_index] + 3)->cost = pktlenx;
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
						((nodet[modulox][cpu_index] + 0)->update)->cost = pktlenx;
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


always_inline void activelist_init(){
    act = malloc(MAXCPU*NUMFLOWS*sizeof(activelist_t));
    for(int i=0;i<MAXCPU;i++){
        for(int j=0;j<(NUMFLOWS-1);j++){
            (act+i*NUMFLOWS+j)->flow=NULL;
            (act+i*NUMFLOWS+j)->next=(act+i*NUMFLOWS+j+1);
        }
        (act+i*NUMFLOWS+(NUMFLOWS-1))->flow=NULL;
        (act+i*NUMFLOWS+(NUMFLOWS-1))->next=(act+i*NUMFLOWS+0);
        head_act[i]=tail_act[i]=(act+i*NUMFLOWS+0);
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
always_inline void vstate(flowcount_t * flow,u8 update,u32 cpu_index){
    if(PREDICT_FALSE(update == 1)){
        flowcount_t * j;
        f32 served,credit;
        int oldnbl=nbl[cpu_index]+1;
#ifdef JIM_APPROX /*The exact calculation is not necessary as the drop cost gets cancelled between vq increments and decrements*/
		credit = (t[cpu_index]-old_t[cpu_index]);
#else	/*Exact value of credit calculation in which the clock cycles spent in dropping the packets is subtracted. */
		credit = (((t[cpu_index]-old_t[cpu_index])) - (n_drops[cpu_index]*(error_cost[cpu_index]+dpdk_cost_total[cpu_index])));
#endif
		threshold[cpu_index] = (credit*((f32)(1.15)))/nbl[cpu_index];

        while (oldnbl>nbl[cpu_index] && nbl[cpu_index] > 0){
            oldnbl = nbl[cpu_index];
            served = credit/(nbl[cpu_index]);
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

    if (PREDICT_TRUE(flow != NULL)){
        if (flow->vqueue == 0){
            nbl[cpu_index]++;
            flowin_act(flow,cpu_index);
        }
		flow->vqueue += flow->cost;
		sum[cpu_index]+=flow->weight;
    }
}

/* arrival function for each packet */
always_inline u8 arrival(flowcount_t * flow,u32 cpu_index,u16 pktlenx){

    if(PREDICT_TRUE(flow->vqueue <= threshold[cpu_index])){
        vstate(flow,0,cpu_index);
#ifdef BUSYLOOP
        if(PREDICT_FALSE(pktlenx > 500))
//		busyloop[cpu_index]+=pktlenx-(dpdk_cost_total[cpu_index]+WEIGHT_IP4E);
		busyloop[cpu_index]+=pktlenx-(WEIGHT_DPDK+WEIGHT_IP4E);
#endif
        return 0;
    }
    else {
        return 1;
    }

#ifdef ELOG_FAIRDROP
	ELOG_TYPE_DECLARE (e) = {
    .format = "Flow Hash: %u Flow Vqueue = %u Threshold = %u cost = %u",
    .format_args = "i4i4i4i2",
	};
  	struct {u32 flow_hash; u32 flow_vqueue;u32 threshold;u16 cost;} *ed;
  	ed = ELOG_DATA (&vlib_global_main.elog_main, e);
  	ed->flow_hash = flow->hash;
  	ed->flow_vqueue = flow->vqueue;
	ed->threshold = threshold[cpu_index];
  	ed->cost = flow->cost;
#endif
}

always_inline u8 fq (u32 modulox, u32 hashx0, u16 pktlenx, u32 cpu_index){
    flowcount_t * i;
    u8 drop;
    i = flow_table_classify(modulox, hashx0, pktlenx, cpu_index);
    drop = arrival(i,cpu_index,pktlenx);
    return drop;
}

/*Function to update costs*/
always_inline void update_costs(u32 cpu_index){

	activelist_t * costlist = head_af[cpu_index];
	flowcount_t * flow0;
	f64 total = (f64)s_total[cpu_index];
	f64 su = (f64)sum[cpu_index];
	while(costlist != NULL){
		flow0 = costlist->flow;
		flow0->cost = flow0->weight*(total/su);
		costlist = costlist->next;
	}
}

always_inline void departure (u32 cpu_index){
    vstate(NULL,1,cpu_index);
	sum[cpu_index]=0;
}

always_inline void sleep_now (u32 t){
	clib_cpu_time_wait(t);
}


#endif /*FLOW_TABLE_H*/

/*
*   "Gather ye rosebuds while ye may"
*                  - Mike Portnoy
*
*   End
*
*/

