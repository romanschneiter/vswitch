/*
     This file (was) part of GNUnet.
     Copyright (C) 2010, 2012, 2018 Christian Grothoff

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
 * @file glab.h
 * @brief Protocol definitions for network-driver
 * @author Christian Grothoff
 */

#ifndef GLAB_IPC_H
#define GLAB_IPC_H

#define _GNU_SOURCE
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stddef.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <byteswap.h>
#include <linux/if.h>
#include <linux/if_tun.h>


/**
 * gcc 4.x-ism to pack structures (to be used before structs);
 * Using this still causes structs to be unaligned on the stack on Sparc
 * (See #670578 from Debian).
 */
_Pragma("pack(push)") _Pragma("pack(1)")

/**
 * Header for all communications between components.
 */
struct GLAB_MessageHeader
{

  /**
   * The length of the struct (in bytes, including the length field itself),
   * in big-endian format.
   */
  uint16_t size;

  /**
   * The type of the message. 0 for 'control' (commands, feedback for
   * user), otherwise packets received from or to be sent to an
   * adapter. The first control message includes the list of all MAC
   * addresses in the body. In all other cases, type is used to
   * specify the number of the adapter (counting from 1).
   */
  uint16_t type;

};


/**
 * Number of bytes in a MAC.
 */
#define MAC_ADDR_SIZE 6


/**
 * A MAC Address.
 */
struct MacAddress
{
  uint8_t mac[MAC_ADDR_SIZE];
};


_Pragma("pack(pop)")


/**
 * Process frame received from @a interface.
 *
 * @param interface number of the interface on which we received @a frame
 * @param frame the frame
 * @param frame_size number of bytes in @a frame
 */
typedef void
(*FrameHandler)(uint16_t interface,
                const void *frame,
                size_t frame_size);

/**
 * Handle control message @a cmd.
 *
 * @param cmd text the user entered
 * @param cmd_len length of @a cmd
 */
typedef void
(*ControlHandler)(char *cmd,
                  size_t cmd_len);

/**
 * Handle MAC information @a mac
 *
 * @param ifc_num number of the interface with @a mac
 * @param mac the MAC address at @a ifc_num
 */
typedef void
(*MacHandler)(uint16_t ifc_num,
              const struct MacAddress *mac);


/**
 * Sample main loop.  Reads packets from STDIN_FILENO and calls fh(),
 * ch() or mh() on each depending on the type.
 */
void
loop (FrameHandler fh,
      ControlHandler ch,
      MacHandler mh);


/**
 * Helper function to deal with partial writes.
 * Fails hard (calls exit() on failures)!
 *
 * @param fd where to write to
 * @param buf what to write
 * @param buf_size number of bytes in @a buf
 */
void
write_all (int fd,
           const void *buf,
           size_t buf_size);


/**
 * Print message to the user by sending to parent.
 *
 * @param fmt format string
 * @param ... arguments for @a fmt
 */
void
print (const char *fmt,
       ...)  __attribute__ ((format (gnu_printf, 1, 2)));

/**
 * Calculate the checksum of a buffer in one step.
 *
 * @param buf buffer to  calculate CRC over (must be 16-bit aligned)
 * @param len number of bytes in hdr, must be multiple of 2
 * @return crc16 value
 */
uint16_t
GNUNET_CRYPTO_crc16_n (const void *buf, size_t len);


#endif
