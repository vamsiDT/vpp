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
//extern u32 nbla;

always_inline void activelist_init(){
    act = malloc(4096*sizeof(activelist_t));
    for(int j=0;j<4095;j++){
        (act+j)->flow=NULL;
        (act+j)->next=(act+j+1);
    }
    (act+4095)->flow=NULL;
    (act+4095)->next=(act+0);
    head_act=tail_act=(act+0);
}


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
		(nodet[modulox] + 0)->vqueue = 0;
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
		(nodet[modulox] + 0)->vqueue = 0;
        flow = nodet[modulox] + 0;
    }

    else if  ((nodet[modulox] + 0)->branchnext == NULL)
    {
        if  ( (nodet[modulox] + 0)->hash != hashx0 )
        {
            numflows++;
            (nodet[modulox] + 1)->hash = hashx0;
            (nodet[modulox] + 0)->branchnext = (nodet[modulox] + 1);
			(nodet[modulox] + 1)->vqueue = 0;
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
				(nodet[modulox] + 2)->vqueue = 0;
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
					(nodet[modulox] + 3)->vqueue = 0;
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
						((nodet[modulox] + 0)->update)->vqueue = 0;
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

always_inline void flowin_act(flowcount_t * flow,u16 queue_id){
    // if(head_act->flow==NULL){
    //     head_act->flow=flow;
    // }
    // else{
        // tail_act=tail_act->next;
/*
		if(((head_act==tail_act)|| (head_act!=tail_act->next))&&(head_act->flow!=NULL)){
				tail_act=tail_act->next;
		}
		else if (head_act==tail_act->next){
			head_act=head_act->next;
			tail_act=tail_act->next;
		}
*/
		if(PREDICT_FALSE(head_act==tail_act->next)){
            head_act=head_act->next;
            tail_act=tail_act->next;
        }
		else if(head_act->flow!=NULL)
			tail_act=tail_act->next;
 	    tail_act->flow=flow;
/*
		if( ((head_act->flow==NULL)&&(head_act==tail_act)) || (head_act!=tail_act->next) ){
        tail_act->flow=flow;
        tail_act=tail_act->next;
		}
		else{
		 printf("overflow\n");
		head_act=head_act->next;
		tail_act->flow=flow;
		tail_act=tail_act->next;
		}
*/
    // }
//     if(head_act->flow==NULL)
//         printf("wrong\n");

}

always_inline flowcount_t * flowout_act(u16 queue_id){

//    if(head_act->flow==NULL)printf("NULL\t");
	flowcount_t * i = head_act->flow;
    head_act->flow=NULL;
//printf("Hi!!!\t");
     if(tail_act!=head_act){
        head_act=head_act->next;
     }
//	if(head_act==tail_act)
//		printf("head=tail\n");
    return i;
}

/* vstate algorithm */
always_inline void vstate(flowcount_t * flow, u16 pktlenx,u8 update,u16 queue_id){

    if(PREDICT_FALSE(update == 1)){
        flowcount_t * j;
//		printf("%u\n",nbl);
        f32 served,credit;
		//f32 served;
        int oldnbl=nbl+1;
//		credit_v=credit;
        credit=(t-old_t)*ALPHA*10;
//		threshold = (credit)/nbl;
//	printf("actual credit=%f\tcredit=%u\tnbl=%u\tserved=%u\n",(t-old_t)*ALPHA*10,credit,nbl,credit/nbl);
        while (oldnbl>nbl && nbl > 0 ){
            oldnbl = nbl;
            served = credit/nbl;
            credit = 0;
            for (int k=0;k<oldnbl;k++){
                j = flowout_act(queue_id);
				//if(j==NULL){printf("%u\n",k);/*continue;*/}//printf("NULL :( on nbl[%u] : %u\n",queue_id,nbl[queue_id]);
                if(j->vqueue > served){
					//if(j->vqueue > THRESHOLD+512)
					//printf("Vqueue vstate%u\t",j->vqueue);
                    j->vqueue -= served;
					//if(j->vqueue > THRESHOLD+512)
					//printf("Vqueue vstate %u\n",j->vqueue);
                    flowin_act(j,queue_id);
                    credit += served - j->vqueue;
					//printf("Flow_in credit = %f\n",credit);
                }
                else{
                    credit += served - j->vqueue;
                    j->vqueue = 0;
                    nbl--;
					//printf("Flow_out credit = %f\n",credit);
                }
            }
        }
    }

    if (flow != NULL){
        if (flow->vqueue == 0){
			if(nbl<4096)
            nbl++;
            flowin_act(flow,queue_id);
			//printf("nbl:%u\tqueue:%u\n",nbl[queue_id],queue_id);
        }
        flow->vqueue += pktlenx;
		// if(flow->vqueue > THRESHOLD+512)
		// printf("Vqueue in %u\n",flow->vqueue);
    }
}

/* arrival function for each packet */
always_inline u8 arrival(struct rte_mbuf * mb,u16 j,flowcount_t * flow,u16 pktlenx,u16 queue_id){
	//printf("arrival %u\n",flow->vqueue);
	//if(flow==NULL)printf("Stupid Motherfucker\n");
    if(flow->vqueue <= THRESHOLD){
        vstate(flow,pktlenx,0,queue_id);
        f_vectors[j]=mb;
//		printf("%u\n",flow->vqueue);
        return 1;
    }
    else {
		//printf("drop %u\n",flow->vqueue);
        rte_pktmbuf_free(mb);
//		printf("drop\n");
        return 0;
        //update vstate is only after a vector. So no update before dropping a packet here.
    }
}
/*
always_inline u8 fq (u32 modulox, u32 hashx0, u16 pktlenx){
    flowcount_t * i;
    u8 drop;
    i = flow_table_classify(modulox,hashx0,pktlenx);
    drop = arrival(i,pktlenx);
    return drop;
}
*/
/*vstate update function before sending the vector. This function is after processing all the packets in the vector and runs only once per vector */
always_inline void departure (u16 queue_id){
    vstate(NULL,0,1,queue_id);
}
#endif /*FLOW_TABLE_H*/

/*
*   "Gather ye rosebuds while ye may"
*                  - Mike Portnoy
*
*   End
*
*/

