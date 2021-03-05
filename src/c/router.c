/*
 *  chirouter - A simple, testable IP router
 *
 *  This module contains the actual functionality of the router.
 *  When a router receives an Ethernet frame, it is handled by
 *  the chirouter_process_ethernet_frame() function.
 *
 */

/*
 * This project is based on the Simple Router assignment included in the
 * Mininet project (https://github.com/mininet/mininet/wiki/Simple-Router) which,
 * in turn, is based on a programming assignment developed at Stanford
 * (http://www.scs.stanford.edu/09au-cs144/lab/router.html)
 *
 * While most of the code for chirouter has been written from scratch, some
 * of the original Stanford code is still present in some places and, whenever
 * possible, we have tried to provide the exact attribution for such code.
 * Any omissions are not intentional and will be gladly corrected if
 * you contact us at borja@cs.uchicago.edu
 */

/*
 *  Copyright (c) 2016-2018, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of The University of Chicago nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <assert.h>

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "chirouter.h"
#include "arp.h"
#include "utils.h"
#include "utlist.h"

//handle ARP messages, ICMP messages directed to the router, and IP datagrams.

bool chirouter_find_match_router(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    iphdr_t* ip_hdr = (iphdr_t*) (frame->raw + sizeof(ethhdr_t));
    chirouter_interface_t *interface;
    for (int i = 0; i < ctx->num_interfaces; i++)
    {
        interface = &ctx->interfaces[i];
        if (in_addr_to_uint32(interface->ip) == ip_hdr->dst)
        {
            return true;
        }
    }
    return false;
}

bool chirouter_find_routing_entry(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    iphdr_t* ip_hdr = (iphdr_t*) (frame->raw + sizeof(ethhdr_t));
    chirouter_rtable_entry_t *routing_entry;
    for (int i = 0; i < ctx->num_rtable_entries; i++)
    {
        routing_entry = &ctx->routing_table[i];
        if ((ip_hdr->dst & in_addr_to_uint32(routing_entry->mask)) 
                                == in_addr_to_uint32(routing_entry->dest))
        {
            return true;
        }
    }
    return false;    
}
/*
 * chirouter_process_ethernet_frame - Process a single inbound Ethernet frame
 *
 * This function will get called every time an Ethernet frame is received by
 * a router. This function receives the router context for the router that
 * received the frame, and the inbound frame (the ethernet_frame_t struct
 * contains a pointer to the interface where the frame was received).
 * Take into account that the chirouter code will free the frame after this
 * function returns so, if you need to persist a frame (e.g., because you're
 * adding it to a list of withheld frames in the pending ARP request list)
 * you must make a deep copy of the frame.
 *
 * chirouter can manage multiple routers at once, but does so in a single
 * thread. i.e., it is guaranteed that this function is always called
 * sequentially, and that there will not be concurrent calls to this
 * function. If two routers receive Ethernet frames "at the same time",
 * they will be ordered arbitrarily and processed sequentially, not
 * concurrently (and with each call receiving a different router context)
 *
 * ctx: Router context
 *
 * frame: Inbound Ethernet frame
 *
 * Returns:
 *   0 on success,
 *
 *   1 if a non-critical error happens
 *
 *   -1 if a critical error happens
 *
 *   Note: In the event of a critical error, the entire router will shut down and exit.
 *         You should only return -1 for issues that would prevent the router from
 *         continuing to run normally. Return 1 to indicate that the frame could
 *         not be processed, but that subsequent frames can continue to be processed.
 */
int chirouter_process_ethernet_frame(chirouter_ctx_t *ctx, ethernet_frame_t *frame)
{
    /* Your code goes here */

    /* Accessing the Ethernet header */
    ethhdr_t* hdr = (ethhdr_t*) frame->raw;

    /* Accessing the IP header */
    iphdr_t* ip_hdr = (iphdr_t*) (frame->raw + sizeof(ethhdr_t));
    uint16_t hdr_type = ntohs(hdr->type);
    if ((hdr_type == ETHERTYPE_IP) || (hdr_type == ETHERTYPE_IPV6))
    {
        if (ip_hdr->dst == in_addr_to_uint32(frame->in_interface->ip))
        {
            if ((ip_hdr->proto = IPPROTO_TCP) || (ip_hdr->proto = IPPROTO_UDP))
            {
            // ICMP dst Port unreachable
            }
            else if (ip_hdr->ttl == 1)
            {
                // ICMP time exceeded
            }
            else if (ip_hdr->proto = IPPROTO_ICMP)
            {
                /* Accessing an ICMP message */
                icmp_packet_t* icmp = (icmp_packet_t*) (frame->raw + sizeof(ethhdr_t) + sizeof(iphdr_t));
                if (icmp->type == ICMPTYPE_ECHO_REQUEST)
                {
                    //ICMPTYPE_ECHO_REPLY 
                }
                else 
                {
                    // do nothing
                }
            }
            else 
            {
                // ICMP destination protocol unreachable
            }
        }
        else if (chirouter_find_match_router(ctx, frame))
        {
            // ICMP HOST UNREACHABLE
        }
        else
        {
            if (chirouter_find_routing_entry(ctx, frame))
            {
                pthread_mutex_lock(&(ctx->lock_arp));
                chirouter_arpcache_entry_t* arpcache_entry = chirouter_arp_cache_lookup(ctx, uint32_to_in_addr(ip_hdr->dst)); // struct in_addr
                pthread_mutex_unlock(&(ctx->lock_arp));
                if (arpcache_entry == NULL)
                {
                    chirouter_pending_arp_req_t* pending_req = chirouter_arp_pending_req_lookup(ctx, uint32_to_in_addr(ip_hdr->dst));
                    if (pending_req == NULL)
                    {
                        pthread_mutex_lock(&(ctx->lock_arp));
                        chirouter_send_arp_message(ctx, frame->in_interface, NULL, ip_hdr->dst, ARP_OP_REQUEST);
                        pending_req = chirouter_arp_pending_req_add(ctx, uint32_to_in_addr(ip_hdr->dst),frame->in_interface);
                        chirouter_arp_pending_req_add_frame(ctx, pending_req, frame);
                        pthread_mutex_unlock(&(ctx->lock_arp));
                    }
                    else
                    {
                        pthread_mutex_lock(&(ctx->lock_arp));
                        chirouter_arp_pending_req_add_frame(ctx, pending_req, frame);
                        pthread_mutex_unlock(&(ctx->lock_arp));
                    }
                }
                else
                {
                    // forward the datagram;
                    // find the correct entry, gateway
                    // update TTL and checksum

                }
            }
            else 
            {
                // ICMP network unreachable
            }
        }
        return 0;
    }
    else if (hdr_type == ETHERTYPE_ARP) 
    {
        /* Accessing an ARP message */
        arp_packet_t* arp = (arp_packet_t*) (frame->raw + sizeof(ethhdr_t));
        if (ip_hdr->dst == in_addr_to_uint32(frame->in_interface->ip))
        {
            if (ntohs(arp->op) == ARP_OP_REPLY)
            {
                pthread_mutex_lock(&(ctx->lock_arp));
                int result = chirouter_arp_cache_add(ctx, uint32_to_in_addr(arp->spa), arp->sha); 
                pthread_mutex_unlock(&(ctx->lock_arp));
                if (result != 0)
                {
                    // chilog DEBUG
                }
                // forward withheld frames - decrement TTL - checksum
                // remove the pending ARP request from the pending ARP request list
            } 
            else if (ntohs(arp->op) == ARP_OP_REQUEST)
            {
                // send arp reply
                chirouter_send_arp_message(ctx, frame->in_interface, 
                                    arp->sha, arp->spa,
                                    ARP_OP_REPLY); 
            }
        }
        else
        {
            return 0;
        }
        return 0;
    }
}


