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
#define TABLESIZE 128
#define MAXCPU 4
#define ALPHACPU 1.0
#define THRESHOLD 48640//44800//15000//14000//12800

//#define ELOG_FAIRDROP
//#define ELOG_DPDK_COST
#define BUSYLOOP

#define WEIGHT_IP4	320
#define WEIGHT_IP6	510
#define WEIGHT_DROP 40

#ifdef ELOG_FAIRDROP
#define WEIGHT_DPDK 250
#else
#define WEIGHT_DPDK 200//185
#endif

#define WEIGHT_IP4E 192

#ifdef BUSYLOOP
#define FLOW_HASH_4157820474    2000    //192.168.0.1
#define FLOW_HASH_2122681738    2000 //192.168.0.3
#define FLOW_HASH_3010998242    500    //192.168.0.5
#define FLOW_HASH_976153682     500   //192.168.0.7
#define FLOW_HASH_1434910422    500    //192.168.0.9
#define FLOW_HASH_3704634726    500   //192.168.0.11
#define FLOW_HASH_288202510     500    //192.168.0.13
#define FLOW_HASH_2558221502    500    //192.168.0.15
#define FLOW_HASH_653891148     500    //192.168.0.17
#define FLOW_HASH_2947503612    500    //192.168.0.19
#define FLOW_HASH_1649604500    500   //192.168.0.21
#define FLOW_HASH_3942921252    500    //192.168.0.23
#define FLOW_HASH_2225874592    500    //192.168.0.25
#define FLOW_HASH_234546448     500    //192.168.0.27
#define FLOW_HASH_3221702520    500    //192.168.0.29
#define FLOW_HASH_1230079176    500    //192.168.0.31
#define FLOW_HASH_2381030752    500    //192.168.0.32
#define FLOW_HASH_79521488      500    //192.168.0.34
#define FLOW_HASH_3376465080    500    //192.168.0.36
#define FLOW_HASH_1075185416    500    //192.168.0.38
#define FLOW_HASH_DEFAULT       500
#endif

#define FLOW_HASH_DEFAULT       (WEIGHT_DPDK+WEIGHT_IP4E)

#ifdef BUSYLOOP
#define FLOW_COST(hash) (FLOW_HASH_##hash)
#else
#define FLOW_COST(hash) (FLOW_HASH_DEFAULT)
#endif
//#define FLOW_BUSY(hash) (FLOW_HASH_##hash - FLOW_HASH_DEFAULT)

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
//    u32 threshold;
//    u32 n_packets;
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
extern u8 hello_world[MAXCPU];
extern u64 s[MAXCPU];
extern u64 s_total[MAXCPU];
extern u64 olds_total[MAXCPU];
extern u8 n_drops[MAXCPU];
extern u32 busyloop[MAXCPU];
extern u64 veryold_t[MAXCPU];
extern f64 sum[MAXCPU];
extern u64 dpdk_cost_total[MAXCPU];
extern u16 error_cost[MAXCPU];
extern error_cost_t * cost_node;
extern f32 threshold[MAXCPU];

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
		cost_node = malloc(MAXCPU*(sizeof(error_cost_t)));
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


/* function to insert the flow in blacklogged flows list. The flow is inserted at the end of the list i.e tail.*/
always_inline void flowin(flowcount_t * flow,u32 cpu_index){
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
always_inline flowcount_t * flowout(u32 cpu_index){
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
		credit = (((t[cpu_index]-old_t[cpu_index])) - (n_drops[cpu_index]*(error_cost[cpu_index]+dpdk_cost_total[cpu_index])));
		threshold[cpu_index] = credit/nbl[cpu_index];
		threshold[cpu_index+1] = credit;
		nbl[cpu_index+1]=nbl[cpu_index];
        while (oldnbl>nbl[cpu_index] && nbl[cpu_index] > 0){
            oldnbl = nbl[cpu_index];
            served = credit/(nbl[cpu_index]);
			//threshold[cpu_index]+=served;
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
        }
//		flow->n_packets++;
		flow->vqueue += flow->cost;
		sum[cpu_index]+=flow->weight;
    }
}

/* arrival function for each packet */
always_inline u8 arrival(flowcount_t * flow,u32 cpu_index,u16 pktlenx){
u8 drop;
    if(flow->vqueue <= threshold[cpu_index] /*&& r_qtotal < BUFFER*/){
        vstate(flow,0,cpu_index);
        drop = 0;
#ifdef BUSYLOOP
        if(PREDICT_FALSE(pktlenx > 500))
		busyloop[cpu_index]+=pktlenx-(dpdk_cost_total[cpu_index]+WEIGHT_IP4E);
#endif
    }
    else {
        drop = 1;
		n_drops[cpu_index]++;
    }

#ifdef ELOG_FAIRDROP
	ELOG_TYPE_DECLARE (e) = {
    .format = "Flow Hash: %u Flow Vqueue = %u Threshold = %u Error Cost = %u",
    .format_args = "i4i4i4i4",
	};
  	struct {u32 flow_hash; u32 flow_vqueue;u32 threshold;u32 cost;} *ed;
  	ed = ELOG_DATA (&vlib_global_main.elog_main, e);
  	ed->flow_hash = threshold[cpu_index+1];
  	ed->flow_vqueue = nbl[cpu_index+1];
	ed->threshold = threshold[cpu_index];
  	ed->cost = nbl[cpu_index];
#endif

	return drop;
}

always_inline u8 fq (u32 modulox, u32 hashx0, u16 pktlenx, u32 cpu_index){
    flowcount_t * i;
    u8 drop;
    i = flow_table_classify(modulox, hashx0, pktlenx, cpu_index);
    drop = arrival(i,cpu_index,pktlenx);
    return drop;
}

/*Function to update costs*/
always_inline void update_costs(vlib_main_t *vm,u32 cpu_index){

	// if(PREDICT_FALSE(dpdk_node[cpu_index]==NULL)){
	// 	dpdk_node[cpu_index]=malloc(sizeof(dpdk_node_t));
	// 	memset(dpdk_node[cpu_index],0,sizeof(dpdk_node_t));
	// }

	if (PREDICT_FALSE(cost_node!=NULL)){
	u16 error_drop_cost;
	vlib_node_t *drop_cost = vlib_get_node_by_name (vm, (u8 *) "error-drop");
	vlib_node_sync_stats (vm, drop_cost);
	error_drop_cost = (f64)(drop_cost->stats_total.clocks - (cost_node+cpu_index)->clocks)/(f64)(drop_cost->stats_total.vectors - (cost_node+cpu_index)->vectors);
	(cost_node+cpu_index)->clocks = drop_cost->stats_total.clocks;
	(cost_node+cpu_index)->vectors = drop_cost->stats_total.vectors;
	error_cost[cpu_index]=error_drop_cost;
	}

	 activelist_t * costlist = head_af[cpu_index];
    while(costlist != NULL){
        flowcount_t * flow = costlist->flow;
		f64 total = s_total[cpu_index]-(n_drops[cpu_index]*(dpdk_cost_total[cpu_index]+error_cost[cpu_index]));
        flow->cost = (flow->weight)*(total/sum[cpu_index]);
//		flow->n_packets = 0;
	//flow->threshold=0;
        costlist = costlist->next;
    }
}

always_inline void departure (u32 cpu_index){
    vstate(NULL,1,cpu_index);
	n_drops[cpu_index]=0;
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

