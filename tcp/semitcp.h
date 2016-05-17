/* -*-  Mode:C++; c-basic-offset:8; tab-width:8; indent-tabs-mode:t -*- */
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
 *  This product includes software developed by the Computer Systems
 *  Engineering Group at Lawrence Berkeley Laboratory.
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
#ifndef SEMITCP_H
#define SEMITCP_H

#include"mac-802_11.h"
#define MAXHISTORY	200
#include <stdio.h>
#include <unordered_set>
#include <algorithm>
#include <stdlib.h>
#include <sys/types.h>
#include "ip.h"
#include "tcp.h"
#include "flags.h"
#include "scoreboard.h"
#include "scoreboard-rq.h"
#include "random.h"
#define TRUE    1
#define FALSE   0
#define RECOVER_DUPACK  1
#define RECOVER_TIMEOUT 2
#define RECOVER_QUENCH  3

class SemiTcpAgent; 	//forward declaration
class TcpBackoffTimer : public TimerHandler
{
public:
	TcpBackoffTimer(SemiTcpAgent *a) : a_(a) { }
private:
	virtual void expire(Event *e);
	SemiTcpAgent *a_;
};

class SemiTcpAgent : public TcpAgent
{
	friend class TcpBackoffTimer;
public:
        SemiTcpAgent();
        virtual void recv (Packet *pkt, Handler*);
        virtual void timeout (int tno);
        int command ( int argc, const char*const* argv );
private:
		void backoffHandler();
		void inr_cw(){
			if (cw_ < 64)
				cw_ << 1;
		}
		void decr_cw(){
			if (cw_ > 1)
				cw_ >> 1;
		}
		void reset_cw(){ cw_ = 1; }
		void setBackoffTimer()
		{
			if (backoffTimer_.status() != TIMER_PENDING)
			{
				backoffTimer_.resched((Random::random() % cw_) * timeslot);
			}
		}
		void resetBackoffTimer()
		{
			backoffTimer_.force_cancel();
			backoffTimer_.resched((Random::random() % cw_) * timeslot);
		}
        virtual void output ( int seqno, int reason = 0 );
        virtual void recv_newack_helper ( Packet *pkt );
        virtual void send_much ( int force, int reason, int maxburst );
        virtual void set_rtx_timer();
		void reset_rtx_timer(int);
		void newack ( Packet* pkt );

        Mac802_11* p_to_mac;
        TcpBackoffTimer backoffTimer_;
		unordered_set<int> outgoingPkts;
		int cw_; 
		double timeslot;
		bool isFirstPacket_;
};
#endif
