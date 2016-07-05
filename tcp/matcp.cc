/* -*-	Mode:C++; c-basic-offset:8; tab-width:8; indent-tabs-mode:t -*- */
/*
 * Copyright (c) 1991-1997 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the Computer Systems
 *	Engineering Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include<set>
#include "ip.h"
#include "tcp.h"
#include "matcp.h"
#include"timer-handler.h"
#include <algorithm>
#include <unistd.h>

using namespace std;

void TcpSendTimer::expire(Event* e)
{
	a_->send_timeout();
}

static class SemiTcpClass : public TclClass
{
public:
        SemiTcpClass() : TclClass ( "Agent/TCP/Semi" ) {}
        TclObject* create ( int, const char*const* ) {
                return ( new MaTcpAgent() );
        }
} class_semi;

MaTcpAgent::MaTcpAgent() : 
			sendTime_(0.0),
			minSendTime_(10000.0),
			p_to_mac(nullptr),
			sendTimer_(this),
			needRetransmit(false),
			congestedCount(0),
			retryCount(0),
			maxRetryCount(0),
			notCongestedCount(0),
			retransmitCount(0),
			incrTimeCount(0),
			decrTimeCount(0),
			underFlowCount(0),
			notChangeTimeCount(0)
{ 
	
}

void MaTcpAgent::recv(Packet *pkt, Handler *h)
{
	hdr_tcp *tcph = hdr_tcp::access(pkt);
	
	//int valid_ack = 0;
	if (qs_approved_ == 1 && tcph->seqno() > last_ack_) 
		endQuickStart();
	if (qs_requested_ == 1)
		processQuickStart(pkt);

	/* W.N.: check if this is from a previous incarnation */
	if (tcph->ts() < lastreset_) {
		// Remove packet and do nothing
		Packet::free(pkt);
		return;
	}
	++nackpack_;
	ts_peer_ = tcph->ts();
	int ecnecho = hdr_flags::access(pkt)->ecnecho();
	if (ecnecho && ecn_)
		ecn(tcph->seqno());
	recv_helper(pkt);
	recv_frto_helper(pkt);
	/* grow cwnd and check if the connection is done */ 
	if (tcph->seqno() > last_ack_) {
		recv_newack_helper(pkt);
		if (last_ack_ == 0 && delay_growth_) { 
			cwnd_ = initial_window();
		}
	} else if (tcph->seqno() == last_ack_) {
                if (hdr_flags::access(pkt)->eln_ && eln_) {
                        tcp_eln(pkt);
                        return;
                }
		if (++dupacks_ == numdupacks_ && !noFastRetrans_) {
			dupack_action();
		} else if (dupacks_ < numdupacks_ && singledup_ ) {
			send_one();
		}
	}

	if (QOption_ && EnblRTTCtr_)
		process_qoption_after_ack (tcph->seqno());

	//if (tcph->seqno() >= last_ack_)  
		// Check if ACK is valid.  Suggestion by Mark Allman. 
		//valid_ack = 1;
	Packet::free(pkt);
	/*
	 * Try to send more data.
	 */
	//if (valid_ack || aggressive_maxburst_)
		//send_much(0, 0, maxburst_);
}

void MaTcpAgent::send_much(int force, int reason, int maxburst)
{
	send_idle_helper();

	delsnd_timer_.force_cancel();

	/* Save time when first packet was sent, for newreno  --Allman */
	if (t_seqno_ == 0)
		firstsent_ = Scheduler::instance().clock();

	if (t_seqno_ < curseq_) {
			output(t_seqno_, reason);
			if (QOption_)
				process_qoption_after_send () ; 
			t_seqno_ ++ ;
	}
		
	/* call helper function */
	send_helper(maxburst);
}

void MaTcpAgent::send_timeout()
{
	if (needRetransmit)
	{
		retransmitCount++;
		output(highest_ack_+1, TCP_REASON_DUPACK);
		needRetransmit = false;
	}
	else
	{
		send_much(1, 0, 1);
	}
	// Do not need to reschedule sendTimer. MAC will reschedule it.
	//reset_cw();
}

int MaTcpAgent::command ( int argc, const char*const* argv )
{
        if ( argc == 3 && strcmp ( argv[1], "semitcp-get-mac" ) == 0 ) 
		{
                p_to_mac = ( Mac802_11* ) TclObject::lookup ( argv[2] );		
				return p_to_mac == NULL ? TCL_ERROR : TCL_OK;

        } else if ( argc == 2 && strcmp ( argv[1], "get-highest-acked" ) == 0 ) 
		{
                printf ( "highest acked seqno: %d \n", ( int ) highest_ack_ );
                return TCL_OK;
        }
        else if (argc == 2 && strcmp(argv[1], "emptyCount") == 0)
		{
			fprintf(stderr, "maxRetryCount:\t\t%d\n", maxRetryCount);
			fprintf(stderr, "congestedCount:\t\t%d\n", congestedCount);
			fprintf(stderr, "notCongestedCount:\t%d\n", notCongestedCount);
			fprintf(stderr, "retransmitCount:\t%d\n\n", retransmitCount);
			fprintf(stderr, "    avgSendTime:\t%.2f\n", (p_to_mac->avgSendTime_)*1000);
			fprintf(stderr, "    maxSendTime:\t%.2f\n", (p_to_mac->maxSendTime_)*1000);
			fprintf(stderr, "    minSendTime:\t%.2f\n\n", (p_to_mac->minSendTime_)*1000);
			fprintf(stderr, "     incrTimeCount:\t%d\n", incrTimeCount);
			fprintf(stderr, "     decrTimeCount:\t%d\n", decrTimeCount);
			fprintf(stderr, "    underFlowCount:\t\t%d\n", underFlowCount);
			fprintf(stderr, "notChangeTimeCount:\t%d\n\n", notChangeTimeCount);
			return TCL_OK;
		}
        return TcpAgent::command ( argc, argv );
}

///Called when the retransimition timer times out
void MaTcpAgent::timeout ( int tno )
{
	/* retransmit timer */
	if (tno == TCP_TIMER_RTX) {

		// There has been a timeout - will trace this event
		trace_event("TIMEOUT");

	        if (cwnd_ < 1) cwnd_ = 1;
		if (highest_ack_ == maxseq_ && !slow_start_restart_) {
			/*
			 * TCP option:
			 * If no outstanding data, then don't do anything.  
			 */
			 // Should this return be here?
			 // What if CWND_ACTION_ECN and cwnd < 1?
			 // return;
		} else {
			recover_ = maxseq_;
			if (highest_ack_ == -1 && wnd_init_option_ == 2)
				/* 
				 * First packet dropped, so don't use larger
				 * initial windows. 
				 */
				wnd_init_option_ = 1;
			if (highest_ack_ == maxseq_ && restart_bugfix_)
			       /* 
				* if there is no outstanding data, don't cut 
				* down ssthresh_.
				*/
				slowdown(CLOSE_CWND_ONE);
			else if (highest_ack_ < recover_ &&
			  last_cwnd_action_ == CWND_ACTION_ECN) {
			       /*
				* if we are in recovery from a recent ECN,
				* don't cut down ssthresh_.
				*/
				slowdown(CLOSE_CWND_ONE);
			}
			else {
				++nrexmit_;
				last_cwnd_action_ = CWND_ACTION_TIMEOUT;
				slowdown(CLOSE_SSTHRESH_HALF|CLOSE_CWND_RESTART);
			}
		}
		/* Since:
		   (1) we react upon incipient congestion by throttling the transmission 
		       rate of TCP-AP
		   (2) we rarely get any buffer overflow in multihop networks with consistent
		       link layer bandwidth
		   then we don't need to back off (verified by simulations). 
		 */	
		last_cwnd_action_ = CWND_ACTION_TIMEOUT;
		needRetransmit = true;
		reset_rtx_timer(1, 0);
	}
	else {
		assert(0); 	// would not run to here
		timeout_nonrtx(tno);
	}
}

void MaTcpAgent::dupack_action()
{
	int recovered = (highest_ack_ > recover_);
	if (recovered || (!bug_fix_ && !ecn_)) {
		goto tahoe_action;
	}

	if (ecn_ && last_cwnd_action_ == CWND_ACTION_ECN) {
		last_cwnd_action_ = CWND_ACTION_DUPACK;
		slowdown(CLOSE_CWND_ONE);
		needRetransmit = true;
		reset_rtx_timer(1, 0);
		return;
	}

	if (bug_fix_) {
		/*
		 * The line below, for "bug_fix_" true, avoids
		 * problems with multiple fast retransmits in one
		 * window of data. 
		 */
		return;
	}

tahoe_action:
        recover_ = maxseq_;
        if (!lossQuickStart()) {
		// we are now going to fast-retransmit and willtrace that event
		trace_event("FAST_RETX");
		last_cwnd_action_ = CWND_ACTION_DUPACK;
		slowdown(CLOSE_SSTHRESH_HALF|CLOSE_CWND_ONE);
	}

	needRetransmit = true;
	reset_rtx_timer(1, 0);
	return;
}

void MaTcpAgent::send_one()
{
	// nothing to do
}

void MaTcpAgent::setSendTimer()
{
	//        3*sifs + rts + cts + data + ack
	// 			3288 + 1240 = 4528
	//double data = 24 + 256 + 256 + 2496 + 256;
	//double ack	= 24 + 256 + 256 + 448  + 256;
	static double time = 1 / 1000000;
	
	if (minSendTime_ > 100.0) // first time
	{
		sendTimer_.resched(1 / 1000000);
	}
	else
	{
		if (sendTime_ > minSendTime_ * 1.8)
		{
			incrTimeCount++;
			time += 0.00001; 	// decrease sending rate
		}
		else if (sendTime_ < minSendTime_ * 1.7)
		{
			decrTimeCount++;
			time -= 0.00005; 	// increase sending rate
			
			if (time < 0)
			{
				time += 0.00005;
				underFlowCount++;
			}
		}
		else
		{
			notChangeTimeCount++;
		}
			
		sendTimer_.resched(time);
	}
}