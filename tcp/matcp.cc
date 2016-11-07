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
#include <mac-802_11.h>
#include <algorithm>
#include <unistd.h>

using namespace std;

static const int CONVERT_THRESHOLD = 7;
static const int SAMPLE_COUNT = 10;
static const double elips = 1000.0; 	// 1kbps
static const double MAX_RATIO = 0.5;
static const double MIN_RATIO = 0.3;

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
			RTS_DATA_ratio(0.0),
			min_send_time(0.0),
			max_send_rate(0.0),
			p_to_mac(nullptr),
			sendTimer_(this),
			top_send_rate(0.0),
			bottom_send_rate(0.0),
			curr_send_rate(0.0),
			curr_status(TCPStatus::SEMI_TCP),
			needRetransmit(false),
			congestedCount(0),
			retryCount(0),
			maxRetryCount(0),
			notCongestedCount(0),
			retransmitCount(0),
			incrTimeCount(0),
			decrTimeCount(0),
			underFlowCount(0),
			notChangeTimeCount(0),
			hit_the_max_send_rate(false)
{	
	bind("min_RTS_DATA_ratio", &min_RTS_DATA_ratio);
	bind("max_RTS_DATA_ratio", &max_RTS_DATA_ratio);
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

double MaTcpAgent::Abs(double d) const
{
	if (d < 0.0)
	{
		d = -d;
	}
	return d;
}

void MaTcpAgent::AdjustSendRate()
{
	static deque<double> buffer;
	static int below_count = 0, above_count = 0, inner_count = 0;
	
	buffer.push_back(RTS_DATA_ratio);
	if (RTS_DATA_ratio < min_RTS_DATA_ratio)
	{
		below_count++;
	}
	else if (RTS_DATA_ratio < max_RTS_DATA_ratio)
	{
		inner_count++;
	}
	else
	{
		above_count++;
	}

	if (buffer.size() > SAMPLE_COUNT)
	{
		double oldest = buffer.front();
		buffer.pop_front();
		if (oldest < min_RTS_DATA_ratio)
		{
			below_count--;
		}
		else if (oldest < max_RTS_DATA_ratio)
		{
			inner_count--;
		}
		else
		{
			above_count--;
		}
	}	
	
	double now = Scheduler::instance().clock();
	if (now > 1.0)
	{
		//fprintf(stderr, "min_RTS_DATA_ratio:\t%.2f\tmax_RTS_DATA_ratio:\t%.2f\n", min_RTS_DATA_ratio, max_RTS_DATA_ratio);
		if (curr_status == TCPStatus::SEMI_TCP)
		{
			fprintf(stderr, "%.2f\tSEMI_TCP---RTS_DATA_ratio:\t%.2f\n", Scheduler::instance().clock(), RTS_DATA_ratio);
		}
		else if (curr_status == TCPStatus::SLOW_START)
		{
			fprintf(stderr, "%.2f\tSLOW_START---RTS_DATA_ratio:\t%.2f [%.2f, %.2f]\n", Scheduler::instance().clock(), RTS_DATA_ratio, min_RTS_DATA_ratio, max_RTS_DATA_ratio);
			fprintf(stderr, "curr:\t%.2f\n", curr_send_rate/1000.0);
		}
		else if (curr_status == TCPStatus::SEARCHING)
		{
			fprintf(stderr, "%.2f\tSEARCHING---RTS_DATA_ratio:\t%.2f [%.2f, %.2f]\n", Scheduler::instance().clock(), RTS_DATA_ratio, min_RTS_DATA_ratio, max_RTS_DATA_ratio);
			fprintf(stderr, "curr:\t%.2f [%.2f, %.2f]\n", curr_send_rate/1000.0, bottom_send_rate/1000.0, top_send_rate/1000.0);
		}
		else
		{
			fprintf(stderr, "%.2f\tSTABLE---RTS_DATA_ratio:\t%.2f [%.2f, %.2f]\n", Scheduler::instance().clock(), RTS_DATA_ratio, min_RTS_DATA_ratio, max_RTS_DATA_ratio);
			fprintf(stderr, "curr:\t%.2f\n", curr_send_rate/1000.0);			
		}
	}
	
	if (hit_the_max_send_rate && curr_status != TCPStatus::SEMI_TCP)
	{
		curr_status = TCPStatus::SEARCHING;
		top_send_rate = curr_send_rate;
		bottom_send_rate = 0;
		curr_send_rate /= 2;
		return; 	// WARNING: do not forget
	}
	
	if (curr_status == TCPStatus::SEMI_TCP)
	{
		curr_status = TCPStatus::SLOW_START;
		max_send_rate = (1.0 / min_send_time) * 512 * 8;
		curr_send_rate = max_send_rate / 2;
		max_RTS_DATA_ratio = (RTS_DATA_ratio - 1) * MAX_RATIO + 1;
		min_RTS_DATA_ratio = (RTS_DATA_ratio - 1) * MIN_RATIO + 1;
		p_to_mac->curr_status = MACStatus::SEMI_TCP_RC;
		buffer.clear();
		below_count = 0;
		above_count = 0;
		inner_count = 0;
		sendTimer_.resched(ConvertToTimeInterval(curr_send_rate));
	}
	else if (curr_status == TCPStatus::SLOW_START)
	{
		if (inner_count > CONVERT_THRESHOLD)
		{
			curr_status = TCPStatus::STABLE;
		}
		else if (RTS_DATA_ratio < min_RTS_DATA_ratio)
		{
			curr_send_rate *= 2;
			if (curr_send_rate > max_send_rate)
			{
				curr_send_rate = max_send_rate;
			}
		}
		else if (RTS_DATA_ratio > max_RTS_DATA_ratio)
		{
			curr_status = TCPStatus::SEARCHING;
			top_send_rate = curr_send_rate;
			bottom_send_rate = 0;
			curr_send_rate /= 2;
		}
		else
		{
			//NOTE: do nothing
		}
	}
	else if (curr_status == TCPStatus::SEARCHING)
	{
		if (inner_count > CONVERT_THRESHOLD)
		{
			curr_status = TCPStatus::STABLE;
		}
		else if (RTS_DATA_ratio < min_RTS_DATA_ratio)
		{
			if (Abs(curr_send_rate - top_send_rate) < elips)
			{
				ConvertToSemiTCPStatus();
			}
			else
			{
				bottom_send_rate = curr_send_rate;				
				curr_send_rate = (curr_send_rate + top_send_rate) / 2;
				if (curr_send_rate > max_send_rate)
				{
					curr_send_rate = max_send_rate;
				}
			}
		}
		else if (RTS_DATA_ratio > max_RTS_DATA_ratio)
		{
			if (Abs(curr_send_rate - bottom_send_rate) < elips)
			{
				ConvertToSemiTCPStatus();
			}
			else
			{
				top_send_rate = curr_send_rate;
				if (top_send_rate > max_send_rate)
				{
					top_send_rate = max_send_rate;
				}
				
				curr_send_rate = (curr_send_rate + bottom_send_rate) / 2;
			}
		}
		else
		{
			// NOTE: do nothing
		}
	}
	else 	// curr_status == TCPStatus::STABLE
	{
		if (below_count > CONVERT_THRESHOLD)
		{
			ConvertToSemiTCPStatus();
		}
		else if (above_count > CONVERT_THRESHOLD)
		{
			curr_status = TCPStatus::SEARCHING;
			top_send_rate = curr_send_rate;
			bottom_send_rate = 0;		
			curr_send_rate /= 2;
		}
		else
		{
			// NOTE: do nothing
		}
	}
}

void MaTcpAgent::SendDown()
{
	send_much(1, 0, 1);
}
void MaTcpAgent::ConvertToSemiTCPStatus()
{
	curr_status = TCPStatus::SEMI_TCP;
	p_to_mac->curr_status = MACStatus::SEMI_TCP;
	sendTimer_.force_cancel();
	send_much(1, 0, 1);	
}

double MaTcpAgent::ConvertToTimeInterval(double send_rate) const
{
	return (8.0 * size_ / send_rate);
}

void MaTcpAgent::send_much(int force, int reason, int maxburst)
{
	static const int unacked_size = 128;
	send_idle_helper();

	delsnd_timer_.force_cancel();

	/* Save time when first packet was sent, for newreno  --Allman */
	if (t_seqno_ == 0)
		firstsent_ = Scheduler::instance().clock();
	
	if (needRetransmit) 	// 超时的数据包不是在超时的时候发送出去
	{
		retransmitCount++;
		output(highest_ack_+1, TCP_REASON_DUPACK);
		needRetransmit = false;
	}	
	else if (t_seqno_ < curseq_ && (t_seqno_ - highest_ack_) < unacked_size) {
			output(t_seqno_, reason);
			if (QOption_)
				process_qoption_after_send () ; 
			t_seqno_ ++ ;
	}
		
	/* call helper function */
	send_helper(maxburst);
	if (sendTimer_.status() == TIMER_IDLE && curr_status != TCPStatus::SEMI_TCP)
	{
		double interval = ConvertToTimeInterval(curr_send_rate);
		sendTimer_.resched(interval);
	}
}

enum class STATUS
{
	CAN_SEND,
	CAN_NOT_SEND
};

void MaTcpAgent::send_timeout()
{	
	static deque<STATUS> buffer;
	static const int STATUS_SIZE = 20;
	static const int CAN_NOT_SEND_THRESHOLD = 10;
	static int can_not_send_count = 0;
	
	double interval = ConvertToTimeInterval(curr_send_rate);	
	bool can_send = false;
	if (p_to_mac->TotalCongested())
	{
		//fprintf(stderr, "can not send\n");
		buffer.push_back(STATUS::CAN_NOT_SEND);
		can_not_send_count++;
		
		if (curr_status != TCPStatus::SEMI_TCP)
		{
			sendTimer_.resched(interval);
		}
		can_send = false;
	}
	else
	{
		//fprintf(stderr, "can send\n");
		buffer.push_back(STATUS::CAN_SEND);
		can_send = true;
	}
	
	if (buffer.size() > STATUS_SIZE)
	{
		auto oldest = buffer.front();
		buffer.pop_front();
		if (oldest == STATUS::CAN_NOT_SEND)
		{
			can_not_send_count--;
		}
	}
	
	//fprintf(stderr, "can_not_send_count:\t%d\n", can_not_send_count);
	if (can_not_send_count > CAN_NOT_SEND_THRESHOLD)
	{
		hit_the_max_send_rate = true;
	}
	else
	{
		hit_the_max_send_rate = false;
	}
	
	if (!can_send)
	{
		return; 	// if can not send, just return
	}

	send_much(1, 0, 1); 	// send a new packet
	
	if (curr_status != TCPStatus::SEMI_TCP)
	{
		sendTimer_.resched(interval);
	}
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
			return TCL_OK; 	// nothing to do
			
			/*fprintf(stderr, "maxRetryCount:\t\t%d\n", maxRetryCount);
			fprintf(stderr, "congestedCount:\t\t%d\n", congestedCount);
			fprintf(stderr, "notCongestedCount:\t%d\n", notCongestedCount);
			fprintf(stderr, "retransmitCount:\t%d\n\n", retransmitCount);
			fprintf(stderr, "    avgSendTime:\t%.2f\n", (p_to_mac->avgSendTime_)*1000);
			fprintf(stderr, "    maxSendTime:\t%.2f\n", (p_to_mac->maxSendTime_)*1000);
			fprintf(stderr, "    minSendTime:\t%.2f\n\n", (p_to_mac->minSendTime_)*1000);
			fprintf(stderr, "     incrTimeCount:\t%d\n", incrTimeCount);
			fprintf(stderr, "     decrTimeCount:\t%d\n", decrTimeCount);
			fprintf(stderr, "    underFlowCount:\t\t%d\n", underFlowCount);
			fprintf(stderr, "notChangeTimeCount:\t%d\n\n", notChangeTimeCount);*/
			//return TCL_OK;
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