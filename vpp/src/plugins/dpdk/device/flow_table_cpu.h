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
#define ALPHACPU 1.0
#define THRESHOLD 44800//15000//14000//12800
#define THRESHOLD1 10000

#define WEIGHT_IP4	320
#define WEIGHT_IP6	510
#define WEIGHT_DROP 60

// 0 1 4 6 8 9 12 13 18 19

#define FLOW_HASH_4157820474	750
#define FLOW_HASH_1526211368	1500
#define FLOW_HASH_2705782963	600 //
#define FLOW_HASH_208508321		550 //
#define FLOW_HASH_1553569150	700
#define FLOW_HASH_168567799		450 //
#define FLOW_HASH_4055038060	400
#define FLOW_HASH_2804371173	350 //
#define FLOW_HASH_578167704		340
#define FLOW_HASH_2405256842	350
#define FLOW_HASH_3653826563	360 //
#define FLOW_HASH_1961071889	370 //
#define FLOW_HASH_2302474460	750
#define FLOW_HASH_605525454		700
#define FLOW_HASH_1921131335	650 //
#define FLOW_HASH_3752414805	600 //
#define FLOW_HASH_808097273		550 //
#define FLOW_HASH_2634152171	500 //
#define FLOW_HASH_1723802480	400
#define FLOW_HASH_3415494242	350
#define FLOW_HASH_DEFAULT		320

#define FLOW_COST(hash) (FLOW_HASH_##hash)
//#define FLOW_BUSY(hash) (FLOW_HASH_##hash - FLOW_HASH_DEFAULT)

always_inline u16 flow_costvalue(u32 hash){
u16 cost;
	switch(hash){
		case 4157820474:
			cost = FLOW_COST(4157820474);
			break;
		case 1526211368:
            cost = FLOW_COST(1526211368);
            break;
        case 2705782963:
            cost = FLOW_COST(2705782963);
            break;
        case 208508321:
            cost = FLOW_COST(208508321);
            break;
        case 1553569150:
            cost = FLOW_COST(1553569150);
            break;
        case 168567799:
            cost = FLOW_COST(168567799);
            break;
        case 4055038060:
            cost = FLOW_COST(4055038060);
            break;
        case 2804371173:
            cost = FLOW_COST(2804371173);
            break;
        case 578167704:
            cost = FLOW_COST(578167704);
            break;
        case 2405256842:
            cost = FLOW_COST(2405256842);
            break;
        case 3653826563:
            cost = FLOW_COST(3653826563);
            break;
        case 1961071889:
            cost = FLOW_COST(1961071889);
            break;
        case 2302474460:
            cost = FLOW_COST(2302474460);
            break;
        case 605525454:
            cost = FLOW_COST(605525454);
            break;
        case 1921131335:
            cost = FLOW_COST(1921131335);
            break;
        case 3752414805:
            cost = FLOW_COST(3752414805);
            break;
        case 808097273:
            cost = FLOW_COST(808097273);
            break;
        case 2634152171:
            cost = FLOW_COST(2634152171);
            break;
        case 1723802480:
            cost = FLOW_COST(1723802480);
            break;
        case 3415494242:
            cost = FLOW_COST(3415494242);
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
    u32 n_packets;
	u64 total_packets;
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
extern u64 t1[MAXCPU];
extern u8 hello_world[MAXCPU];
extern u64 s[MAXCPU];
extern u64 s_total[MAXCPU];
extern u8 n_drops[MAXCPU];
extern u32 busyloop[MAXCPU];
extern u64 veryold_t[MAXCPU];
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

extern u32 flows[MAXCPU];

always_inline flowcount_t *
flow_table_classify(u32 modulox, u32 hashx0, u16 pktlenx, u32 cpu_index){

    flowcount_t * flow;
//printf("%u\n",hashx0);
    if (PREDICT_FALSE(head[cpu_index] == NULL)){
        nbl[cpu_index] = 0;
        nodet[modulox][cpu_index] = malloc(4*sizeof(flowcount_t));
		flows[cpu_index]++;
		//printf("%u\n",hashx0);
        (nodet[modulox][cpu_index] + 0)->branchnext = NULL;
        (nodet[modulox][cpu_index] + 1)->branchnext = NULL;
        (nodet[modulox][cpu_index] + 2)->branchnext = NULL;
        (nodet[modulox][cpu_index] + 3)->branchnext = NULL;
        (nodet[modulox][cpu_index] + 0)->hash = hashx0;
        (nodet[modulox][cpu_index] + 0)->weight = pktlenx;
		(nodet[modulox][cpu_index] + 0)->cost = pktlenx;
		(nodet[modulox][cpu_index] + 0)->total_packets = 0;
//		(nodet[modulox][cpu_index] + 0)->vqueue = 800;
        (nodet[modulox][cpu_index] + 0)->update = (nodet[modulox][cpu_index] + 0);
        head[cpu_index] = nodet[modulox][cpu_index] + 0;
        flow = nodet[modulox][cpu_index] + 0;
    }

    else if ( (nodet[modulox][cpu_index] + 0) == NULL ){
        nodet[modulox][cpu_index] = malloc(4*sizeof(flowcount_t));
		flows[cpu_index]++;
		//printf("%u\n",hashx0);
        (nodet[modulox][cpu_index] + 0)->branchnext = NULL;
        (nodet[modulox][cpu_index] + 1)->branchnext = NULL;
        (nodet[modulox][cpu_index] + 2)->branchnext = NULL;
        (nodet[modulox][cpu_index] + 3)->branchnext = NULL;
        (nodet[modulox][cpu_index] + 0)->hash = hashx0;
        (nodet[modulox][cpu_index] + 0)->weight = pktlenx;
		(nodet[modulox][cpu_index] + 0)->cost = pktlenx;
		(nodet[modulox][cpu_index] + 0)->total_packets = 0;
//		(nodet[modulox][cpu_index] + 0)->vqueue = 800;
        (nodet[modulox][cpu_index] + 0)->update = (nodet[modulox][cpu_index] + 0);
        flow = nodet[modulox][cpu_index] + 0;
    }

    else if  ((nodet[modulox][cpu_index] + 0)->branchnext == NULL)
    {
        if  ( (nodet[modulox][cpu_index] + 0)->hash != hashx0 )
        {
            (nodet[modulox][cpu_index] + 1)->hash = hashx0;
            (nodet[modulox][cpu_index] + 1)->weight = pktlenx;
			(nodet[modulox][cpu_index] + 1)->weight = pktlenx;
			(nodet[modulox][cpu_index] + 1)->total_packets = 0;
//			(nodet[modulox][cpu_index] + 0)->vqueue = 800;
            (nodet[modulox][cpu_index] + 0)->branchnext = (nodet[modulox][cpu_index] + 1);
			flows[cpu_index]++;
			//printf("%u\n",hashx0);
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
				(nodet[modulox][cpu_index] + 2)->total_packets = 0;
//				(nodet[modulox][cpu_index] + 0)->vqueue = 800;
                (nodet[modulox][cpu_index] + 1)->branchnext = nodet[modulox][cpu_index] + 2;
				flows[cpu_index]++;
				//printf("%u\n",hashx0);
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
					(nodet[modulox][cpu_index] + 3)->total_packets = 0;
//					(nodet[modulox][cpu_index] + 0)->vqueue = 800;
                    (nodet[modulox][cpu_index] + 2)->branchnext = nodet[modulox][cpu_index] + 3;
                    (nodet[modulox][cpu_index] + 3)->branchnext = nodet[modulox][cpu_index] + 0;
					flows[cpu_index]++;
					//printf("%u\n",hashx0);
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
//printf("%u\n",flows[cpu_index]);
    if(PREDICT_FALSE(update == 1)){
        flowcount_t * j;
        f32 served,credit;
        int oldnbl=nbl[cpu_index]+1;
		//printf("%lu\t%lu\t",t[cpu_index],old_t[cpu_index]);
		//printf("%lu\n",t[cpu_index]-old_t[cpu_index]);
//        if (t[cpu_index] > old_t[cpu_index])
		credit = ((t[cpu_index]-old_t[cpu_index])) /*- (n_drops[cpu_index]*WEIGHT_DROP)*/;
//		else
//		credit = ((old_t[cpu_index]-t[cpu_index]))/*- (n_drops[cpu_index]*WEIGHT_DROP)*/;
		//printf("%lf\n",credit);
        while (oldnbl>nbl[cpu_index] && nbl[cpu_index] > 0){
            oldnbl = nbl[cpu_index];
            served = credit/(nbl[cpu_index]);
			//printf("%lf\t",served);
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
    //printf("\n");
    }

    if (flow != NULL){
        if (flow->vqueue == 0){
            nbl[cpu_index]++;
			//printf("%u\n",nbl[cpu_index]);
            flowin(flow,cpu_index);
			flow->vqueue = 1;
        }
		flow->n_packets++;
		flow->vqueue += flow->cost;
    }
}

/*Drop Probability*/
always_inline void prob(u32 vq){
	f64 proba;
	if(vq >=THRESHOLD1 && vq <= 4*THRESHOLD1)
	proba = 10*( ( ((f64)(vq)) / (f64)(3*THRESHOLD1) ) - ( ((f64)(1)) / ((f64)(3)) ) );
	else if (vq <THRESHOLD1)
		proba = 0;
	else if (vq > 4*THRESHOLD1)
		proba = 1;
	printf("%lf\t",proba);
}

/* arrival function for each packet */
always_inline u8 arrival(flowcount_t * flow,u32 cpu_index){
u8 drop;
//printf("FLOW_VQUEUE:%u\n",flow->vqueue);
    if(flow->vqueue <= THRESHOLD /*&& r_qtotal < BUFFER*/){
        vstate(flow,0,cpu_index);
		flow->total_packets++;
        drop = 0;
    }
    else {
        drop = 1;
		n_drops[cpu_index]++;
    }
//	printf("%u\t%u\t%u\t%u\n",drop,flow->vqueue,THRESHOLD,flow->hash);
return drop;
}

always_inline u8 fq (u32 modulox, u32 hashx0, u16 pktlenx, u32 cpu_index){
    flowcount_t * i;
    u8 drop;
    i = flow_table_classify(modulox, hashx0, pktlenx, cpu_index);
    drop = arrival(i,cpu_index);
	//printf("%u\n",i->hash);
    return drop;
}

/*Function to update costs*/
always_inline void update_costs(vlib_main_t *vm,u32 cpu_index){
    activelist_t * costlist = head_af[cpu_index];
    f64 sum = 0;
//	printf("start\n");
    while (costlist != NULL){
        flowcount_t * flow = costlist->flow;
        sum += ((u32)(flow->weight))*(flow->n_packets);
//		printf("%u:%u\n",flow->weight,flow->n_packets);
		//printf("%u\t%u\n",flow->hash,cpu_index);
        costlist = costlist->next;
    }
//	printf("end: %u\n",n_drops[cpu_index]);
	//sum += (n_drops[cpu_index]*WEIGHT_DROP);
//	printf("drops:%u\t",((u32)n_drops[cpu_index]));
//	printf("sum:%lf\n",sum);
    costlist = head_af[cpu_index];
    while(costlist != NULL){
        flowcount_t * flow = costlist->flow;
        flow->cost = ((f64)((flow->weight)*(s_total[cpu_index] /*-(n_drops[cpu_index]*WEIGHT_DROP)*/)))/ sum;
		flow->n_packets = 0;
		//printf("%f\t",((f64)(s_total[cpu_index]-(n_drops[cpu_index]*WEIGHT_DROP))));
		//printf("%u\t",flow->weight);
		//printf("%u\n",flow->cost);
        costlist = costlist->next;
    }
//	printf("s_total:%lf\tsum:%lf\n",(f64)(s_total[cpu_index]/*-(n_drops[cpu_index]*WEIGHT_DROP)*/),sum);
}

/*function to increment vqueues using the updated costs*/
always_inline void update_vstate(vlib_main_t * vm,u32 cpu_index){
    activelist_t * costlist = head_af[cpu_index];
	u32 totalvqueue=0;
    while(costlist != NULL){
        flowcount_t * flow = costlist->flow;
//		prob(flow->vqueue);
//		printf("%u\n",flow->weight);
        totalvqueue+= flow->vqueue;
        flow->vqueue += (flow->n_packets)*(flow->cost);
		//prob(flow->vqueue);
		//printf("%u\n",flow->weight);
		totalvqueue+= flow->vqueue;
//		printf("%u:%u\n",flow->n_packets,flow->hash);
        flow->n_packets = 0;
        costlist = costlist->next;
    }
	//printf("%u\t",totalvqueue);
}

always_inline void departure (u32 cpu_index){
    vstate(NULL,1,cpu_index);
	n_drops[cpu_index]=0;
//	printf("%u\n",nbl[cpu_index]);
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

