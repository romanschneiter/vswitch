/*
     This file (was) part of GNUnet.
     Copyright (C) 2018 Christian Grothoff

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file harness.h
 * @brief Testing and grading harness header
 * @author Christian Grothoff
 */
#ifndef HARNESS_H
#define HARNESS_H
#include "glab.h"


/**
 * gcc 4.x-ism to pack structures (to be used before structs);
 * Using this still causes structs to be unaligned on the stack on Sparc
 * (See #670578 from Debian).
 */
_Pragma("pack(push)") _Pragma("pack(1)")

struct EthernetHeader
{
  struct MacAddress dst;
  struct MacAddress src;

  /**
   * See ETH_P-values.
   */
  uint16_t tag;
};


/* see http://www.iana.org/assignments/ethernet-numbers */
#ifndef ETH_P_IPV4
/**
 * Number for IPv4
 */
#define ETH_P_IPV4 0x0800
#endif

#ifndef ETH_P_ARP
/**
 * Number for ARP
 */
#define ETH_P_ARP 0x0806
#endif

/* some systems use one underscore only, and mingw uses no underscore... */
#ifndef __BYTE_ORDER
#ifdef _BYTE_ORDER
#define __BYTE_ORDER _BYTE_ORDER
#else
#ifdef BYTE_ORDER
#define __BYTE_ORDER BYTE_ORDER
#endif
#endif
#endif
#ifndef __BIG_ENDIAN
#ifdef _BIG_ENDIAN
#define __BIG_ENDIAN _BIG_ENDIAN
#else
#ifdef BIG_ENDIAN
#define __BIG_ENDIAN BIG_ENDIAN
#endif
#endif
#endif
#ifndef __LITTLE_ENDIAN
#ifdef _LITTLE_ENDIAN
#define __LITTLE_ENDIAN _LITTLE_ENDIAN
#else
#ifdef LITTLE_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#endif
#endif
#endif


/**
 * HTYPE for Ethernet.
 */
#define ARP_HTYPE_ETHERNET 1

/**
 * PTYPE for IPv4.
 */
#define ARP_PTYPE_IPV4 0x800


/**
 * A test command.
 */
struct Command
{

  /**
   * label of the command (for debugging)
   */
  const char *label;

  /**
   * Function to run to execute the command.
   *
   * @return 0 on success
   */
  int (*fun)(void);
};


/**
 * Set destination MAC in @a frame to the MAC of
 * interface @a ifc_num.
 *
 * @param frame[in,out] Ethernet frame, must be large enough
 * @param ifc_num identifies which MAC we should use
 */
void
set_dest_mac (void *frame,
              uint16_t ifc_num);


/**
 * Check that we are receiving NOTHING (for a few seconds).
 *
 * @return 0 on success
 */
int
expect_silence (void);


/**
 * We expect a frame with body @a cls of length @a cls2
 * on interface @e cls3.
 *
 * @param cls closure with bitmask of interfaces to receive on
 * @param ifc interface we got a frame from
 * @param msg frame we received
 * @param msg_len number of bytes in @a msg
 * @param cls frame we expect
 * @param cls2 length of @a cls
 * @param cls3 ignored
 * @return 0 on success, 1 on missmatch
 */
int
expect_multicast (void *cls,
                  uint16_t ifc,
                  const void *msg,
                  size_t msg_len,
                  const void *cls1,
                  ssize_t cls2,
                  uint16_t cls3);


/**
 * We expect a frame with body @a cls of length @a cls2
 * on interface @e cls3.
 *
 * @param cls closure
 * @param ifc interface we got a frame from
 * @param msg frame we received
 * @param msg_len number of bytes in @a msg
 * @param cls1 frame we expect
 * @param cls2 length of @a cls
 * @param cls3 interface we expect to receive from
 * @return 0 on success, 1 on missmatch
 */
int
expect_frame (void *cls,
              uint16_t ifc,
              const void *msg,
              size_t msg_len,
              const void *cls1,
              ssize_t cls2,
              uint16_t cls3);


/**
 * Send message.
 *
 * @param type message type to use (0 = control, other: interface)
 * @param msg payload to send
 * @param msg_len number of bytes in @a msg
 */
void
tsend (uint16_t type,
       const void *msg,
       size_t msg_len);


/**
 * Function called with a message we received.
 *
 * @param cls closure
 * @param type message type (0 = control, other: interface)
 * @param msg the message we got
 * @param msg_len number of bytes in @a msg
 * @param cls1 closure
 * @param cls2 another closure
 * @param cls3 a third closure
 * @return 0 if message was what we expected
 */
typedef int
(*Receiver)(void *cls,
            uint16_t type,
            const void *msg,
            size_t msg_len,
            const void *cls1,
            ssize_t cls2,
            uint16_t cls3);


/**
 * Receive message.
 *
 * @param skip_until_match number of messages we may skip until
 *        the desired message must appear
 * @param recv function to call with the message we got
 * @param recv_cls closure for @a recv
 * @param recv_cls1 read-only closure for @a recv
 * @param recv_cls2 additional length argument for @a recv
 * @param recv_cls3 additional argument for @a recv
 * @return 0 on success
 */
int
trecv (unsigned int skip_until_match,
       Receiver recv,
       void *recv_cls,
       const void *recv_cls1,
       ssize_t recv_cls2,
       uint16_t recv_cls3);


/**
 * Start test and pass traffic from/to child process.
 *
 * @param argc number of arguments in @a argv
 * @param argv 0: binary name (program to test)
 *             1..n: network interface name (e.g. eth0)
 *             n+1: "-"
 *             n+2: child program to launch
 * @return 0 on success
 */
int
meta (struct Command *cmd,
      int argc,
      char **argv);

#endif
