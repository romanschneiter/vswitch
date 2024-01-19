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
 * @file router.c
 * @brief IPv4 router
 * @author Christian Grothoff
 */
#include "glab.h"


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


/**
 * ARP header for Ethernet-IPv4.
 */
struct ArpHeaderEthernetIPv4
{
  /**
   * Must be #ARP_HTYPE_ETHERNET.
   */
  uint16_t htype;

  /**
   * Protocol type, must be #ARP_PTYPE_IPV4
   */
  uint16_t ptype;

  /**
   * HLEN.  Must be #MAC_ADDR_SIZE.
   */
  uint8_t hlen;

  /**
   * PLEN.  Must be sizeof (struct in_addr) (aka 4).
   */
  uint8_t plen;

  /**
   * Type of the operation.
   */
  uint16_t oper;

  /**
   * HW address of sender. We only support Ethernet.
   */
  struct MacAddress sender_ha;

  /**
   * Layer3-address of sender. We only support IPv4.
   */
  struct in_addr sender_pa;

  /**
   * HW address of target. We only support Ethernet.
   */
  struct MacAddress target_ha;

  /**
   * Layer3-address of target. We only support IPv4.
   */
  struct in_addr target_pa;
};


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


#define IP_FLAGS_RESERVED 1
#define IP_FLAGS_DO_NOT_FRAGMENT 2
#define IP_FLAGS_MORE_FRAGMENTS 4
#define IP_FLAGS 7

#define IP_FRAGMENT_MULTIPLE 8

/**
 * Standard IPv4 header.
 */
struct IPv4Header
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
  unsigned int header_length : 4;
  unsigned int version : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
  unsigned int version : 4;
  unsigned int header_length : 4;
#else
  #error byteorder undefined
#endif
  uint8_t diff_serv;

  /**
   * Length of the packet, including this header.
   */
  uint16_t total_length;

  /**
   * Unique random ID for matching up fragments.
   */
  uint16_t identification;

  /**
   * Fragmentation flags and fragmentation offset.
   */
  uint16_t fragmentation_info;

  /**
   * How many more hops can this packet be forwarded?
   */
  uint8_t ttl;

  /**
   * L4-protocol, for example, IPPROTO_UDP or IPPROTO_TCP.
   */
  uint8_t protocol;

  /**
   * Checksum.
   */
  uint16_t checksum;

  /**
   * Origin of the packet.
   */
  struct in_addr source_address;

  /**
   * Destination of the packet.
   */
  struct in_addr destination_address;
};


#define ICMPTYPE_DESTINATION_UNREACHABLE 3
#define ICMPTYPE_TIME_EXCEEDED 11

#define ICMPCODE_NETWORK_UNREACHABLE 0
#define ICMPCODE_HOST_UNREACHABLE 1
#define ICMPCODE_FRAGMENTATION_REQUIRED 4

/**
 * ICMP header.
 */
struct IcmpHeader
{
  uint8_t type;
  uint8_t code;
  uint16_t crc;

  union
  {
    /**
     * Payload for #ICMPTYPE_DESTINATION_UNREACHABLE (RFC 1191)
     */
    struct ih_pmtu
    {
      uint16_t empty;
      uint16_t next_hop_mtu;
    } destination_unreachable;

    /**
     * Unused bytes for #ICMPTYPE_TIME_EXCEEDED.
     */
    uint32_t time_exceeded_unused;

  } quench;

  /* followed by original IP header + first 8 bytes of original IP datagram
     (at least for the two ICMP message types we care about here) */

};
_Pragma("pack(pop)")


/**
 * Per-interface context.
 */
struct Interface
{
  /**
   * MAC of interface.
   */
  struct MacAddress mac;

  /**
   * IPv4 address of interface (we only support one IP per interface!)
   */
  struct in_addr ip;

  /**
   * IPv4 netmask of interface.
   */
  struct in_addr netmask;

  /**
   * Name of the interface.
   */
  char *name;

  /**
   * Number of this interface.
   */
  uint16_t ifc_num;

  /**
   * MTU to enforce for this interface.
   */
  uint16_t mtu;
};


/**
 * Number of available contexts.
 */
static unsigned int num_ifc;

/**
 * All the contexts.
 */
static struct Interface *gifc;


/**
 * Forward @a frame to interface @a dst.
 *
 * @param dst target interface to send the frame out on
 * @param frame the frame to forward
 * @param frame_size number of bytes in @a frame
 */
static void
forward_to (struct Interface *dst,
            const void *frame,
            size_t frame_size)
{
  char iob[frame_size + sizeof (struct GLAB_MessageHeader)];
  struct GLAB_MessageHeader hdr;

  if (frame_size > dst->mtu)
    abort ();
  hdr.size = htons (sizeof (iob));
  hdr.type = htons (dst->ifc_num);
  memcpy (iob,
          &hdr,
          sizeof (hdr));
  memcpy (&iob[sizeof (hdr)],
          frame,
          frame_size);
  write_all (STDOUT_FILENO,
             iob,
             sizeof (iob));
}


/**
 * Create Ethernet frame and forward it via @a ifc to @a target_ha.
 *
 * @param ifc interface to send frame out on
 * @param target destination MAC
 * @param tag Ethernet tag to use
 * @param frame_payload payload to use in frame
 * @param frame_payload_size number of bytes in @a frame_payload
 */
static void
forward_frame_payload_to (struct Interface *ifc,
                          const struct MacAddress *target_ha,
                          uint16_t tag,
                          const void *frame_payload,
                          size_t frame_payload_size)
{
  char frame[sizeof (struct EthernetHeader) + frame_payload_size];
  struct EthernetHeader eh;

  if (frame_payload_size + sizeof (struct EthernetHeader) > ifc->mtu)
    abort ();
  eh.dst = *target_ha;
  eh.src = ifc->mac;
  eh.tag = ntohs (tag);
  memcpy (frame,
          &eh,
          sizeof (eh));
  memcpy (&frame[sizeof (eh)],
          frame_payload,
          frame_payload_size);
  forward_to (ifc,
              frame,
              sizeof (frame));
}


/**
 * Route the @a ip packet with its @a payload.
 *
 * @param origin interface we received the packet from
 * @param ip IP header
 * @param payload IP packet payload
 * @param payload_size number of bytes in @a payload
 */
static void
route (struct Interface *origin,
       const struct IPv4Header *ip,
       const void *payload,
       size_t payload_size)
{
  /* TODO: do work here */
}


/**
 * Process ARP (request or response!)
 *
 * @param ifc interface we received the ARP request from
 * @param eh ethernet header
 * @param ah ARP header
 */
static void
handle_arp (struct Interface *ifc,
            const struct EthernetHeader *eh,
            const struct ArpHeaderEthernetIPv4 *ah)
{
  /* TODO: do work here */
}


/**
 * Parse and process frame received on @a ifc.
 *
 * @param ifc interface we got the frame on
 * @param frame raw frame data
 * @param frame_size number of bytes in @a frame
 */
static void
parse_frame (struct Interface *ifc,
             const void *frame,
             size_t frame_size)
{
  struct EthernetHeader eh;
  const char *cframe = frame;

  if (frame_size < sizeof (eh))
  {
    fprintf (stderr,
             "Malformed frame\n");
    return;
  }
  memcpy (&eh,
          frame,
          sizeof (eh));
  switch (ntohs (eh.tag))
  {
  case ETH_P_IPV4:
    {
      struct IPv4Header ip;

      if (frame_size < sizeof (struct EthernetHeader) + sizeof (struct
                                                                IPv4Header))
      {
        fprintf (stderr,
                 "Malformed frame\n");
        return;
      }
      memcpy (&ip,
              &cframe[sizeof (struct EthernetHeader)],
              sizeof (struct IPv4Header));
      /* TODO: possibly do work here (ARP learning) */
      route (ifc,
             &ip,
             &cframe[sizeof (struct EthernetHeader) + sizeof (struct
                                                              IPv4Header)],
             frame_size - sizeof (struct EthernetHeader) - sizeof (struct
                                                                   IPv4Header));
      break;
    }
  case ETH_P_ARP:
    {
      struct ArpHeaderEthernetIPv4 ah;

      if (frame_size < sizeof (struct EthernetHeader) + sizeof (struct
                                                                ArpHeaderEthernetIPv4))
      {
#if DEBUG
        fprintf (stderr,
                 "Unsupported ARP frame\n");
#endif
        return;
      }
      memcpy (&ah,
              &cframe[sizeof (struct EthernetHeader)],
              sizeof (struct ArpHeaderEthernetIPv4));
      handle_arp (ifc,
                  &eh,
                  &ah);
      break;
    }
  default:
#if DEBUG
    fprintf (stderr,
             "Unsupported Ethernet tag %04X\n",
             ntohs (eh.tag));
#endif
    return;
  }
}


/**
 * Process frame received from @a interface.
 *
 * @param interface number of the interface on which we received @a frame
 * @param frame the frame
 * @param frame_size number of bytes in @a frame
 */
static void
handle_frame (uint16_t interface,
              const void *frame,
              size_t frame_size)
{
  if (interface > num_ifc)
    abort ();
  parse_frame (&gifc[interface - 1],
               frame,
               frame_size);
}


/**
 * Find network interface by @a name.
 *
 * @param name name to look up by
 * @return NULL if @a name was not found
 */
static struct Interface *
find_interface (const char *name)
{
  for (unsigned int i = 0; i<num_ifc; i++)
    if (0 == strcasecmp (name,
                         gifc[i].name))
      return &gifc[i];
  return NULL;
}


/**
 * The user entered an "arp" command.  The remaining
 * arguments can be obtained via 'strtok()'.
 */
static void
process_cmd_arp ()
{
  const char *tok = strtok (NULL, " ");
  struct in_addr v4;
  struct MacAddress mac;
  struct Interface *ifc;

  if (NULL == tok)
  {
    // print_arp_cache ();
    return;
  }
  if (1 !=
      inet_pton (AF_INET,
                 tok,
                 &v4))
  {
    fprintf (stderr,
             "`%s' is not a valid IPv4 address\n",
             tok);
    return;
  }
  tok = strtok (NULL, " ");
  if (NULL == tok)
  {
    fprintf (stderr,
             "No network interface provided\n");
    return;
  }
  ifc = find_interface (tok);
  if (NULL == ifc)
  {
    fprintf (stderr,
             "Interface `%s' unknown\n",
             tok);
    return;
  }
  /* TODO: do MAC lookup */
}


/**
 * Parse network specification in @a net, initializing @a network and @a netmask.
 * Format of @a net is "IP/NETMASK".
 *
 * @param network[out] network specification to initialize
 * @param netmask[out] netmask specification to initialize
 * @param arg interface specification to parse
 * @return 0 on success
 */
static int
parse_network (struct in_addr *network,
               struct in_addr *netmask,
               const char *net)
{
  const char *tok;
  char *ip;
  unsigned int mask;

  tok = strchr (net, '/');
  if (NULL == tok)
  {
    fprintf (stderr,
             "Error in network specification: lacks '/'\n");
    return 1;
  }
  ip = strndup (net,
                tok - net);
  if (1 !=
      inet_pton (AF_INET,
                 ip,
                 network))
  {
    fprintf (stderr,
             "IP address `%s' malformed\n",
             ip);
    free (ip);
    return 1;
  }
  free (ip);
  tok++;
  if (1 !=
      sscanf (tok,
              "%u",
              &mask))
  {
    fprintf (stderr,
             "Netmask `%s' malformed\n",
             tok);
    return 1;
  }
  if (mask > 32)
  {
    fprintf (stderr,
             "Netmask invalid (too large)\n");
    return 1;
  }
  netmask->s_addr = htonl (~(uint32_t) ((1LLU << (32 - mask)) - 1LLU));
  return 0;
}


/**
 * Parse route from arguments in strtok() buffer.
 *
 * @param target_network[out] set to target network
 * @param target_netmask[out] set to target netmask
 * @param next_hop[out] set to next hop
 * @param ifc[out] set to target interface
 */
static int
parse_route (struct in_addr *target_network,
             struct in_addr *target_netmask,
             struct in_addr *next_hop,
             struct Interface **ifc)
{
  char *tok;

  tok = strtok (NULL, " ");
  if ( (NULL == tok) ||
       (0 != parse_network (target_network,
                            target_netmask,
                            tok)) )
  {
    fprintf (stderr,
             "Expected network specification, not `%s'\n",
             tok);
    return 1;
  }
  tok = strtok (NULL, " ");
  if ( (NULL == tok) ||
       (0 != strcasecmp ("via",
                         tok)))
  {
    fprintf (stderr,
             "Expected `via', not `%s'\n",
             tok);
    return 1;
  }
  tok = strtok (NULL, " ");
  if ( (NULL == tok) ||
       (1 != inet_pton (AF_INET,
                        tok,
                        next_hop)) )
  {
    fprintf (stderr,
             "Expected next hop, not `%s'\n",
             tok);
    return 1;
  }
  tok = strtok (NULL, " ");
  if ( (NULL == tok) ||
       (0 != strcasecmp ("dev",
                         tok)))
  {
    fprintf (stderr,
             "Expected `dev', not `%s'\n",
             tok);
    return 1;
  }
  tok = strtok (NULL, " ");
  *ifc = find_interface (tok);
  if (NULL == *ifc)
  {
    fprintf (stderr,
             "Interface `%s' unknown\n",
             tok);
    return 1;
  }
  return 0;
}


/**
 * Add a route.
 */
static void
process_cmd_route_add ()
{
  struct in_addr target_network;
  struct in_addr target_netmask;
  struct in_addr next_hop;
  struct Interface *ifc;

  if (0 != parse_route (&target_network,
                        &target_netmask,
                        &next_hop,
                        &ifc))
    return;
  /* TODO: Add routing table entry */
}


/**
 * Delete a route.
 */
static void
process_cmd_route_del ()
{
  struct in_addr target_network;
  struct in_addr target_netmask;
  struct in_addr next_hop;
  struct Interface *ifc;

  if (0 != parse_route (&target_network,
                        &target_netmask,
                        &next_hop,
                        &ifc))
    return;
  /* TODO: Delete routing table entry */
}


/**
 * Print out the routing table.
 */
static void
process_cmd_route_list ()
{
  /* TODO: show routing table with 'print' */
}


/**
 * The user entered a "route" command.  The remaining
 * arguments can be obtained via 'strtok()'.
 */
static void
process_cmd_route ()
{
  char *subcommand = strtok (NULL, " ");

  if (NULL == subcommand)
    subcommand = "list";
  if (0 == strcasecmp ("add",
                       subcommand))
    process_cmd_route_add ();
  else if (0 == strcasecmp ("del",
                            subcommand))
    process_cmd_route_del ();
  else if (0 == strcasecmp ("list",
                            subcommand))
    process_cmd_route_list ();
  else
    fprintf (stderr,
             "Subcommand `%s' not understood\n",
             subcommand);
}


/**
 * Parse network specification in @a net, initializing @a ifc.
 * Format of @a net is "IPV4:IP/NETMASK".
 *
 * @param ifc[out] interface specification to initialize
 * @param arg interface specification to parse
 * @return 0 on success
 */
static int
parse_network_arg (struct Interface *ifc,
                   const char *net)
{
  if (0 !=
      strncasecmp (net,
                   "IPV4:",
                   strlen ("IPV4:")))
  {
    fprintf (stderr,
             "Interface specification `%s' does not start with `IPV4:'\n",
             net);
    return 1;
  }
  net += strlen ("IPV4:");
  return parse_network (&ifc->ip,
                        &ifc->netmask,
                        net);
}


/**
 * Parse interface specification @a arg and update @a ifc.  Format is
 * "IFCNAME[IPV4:IP/NETMASK]=MTU".  The "=MTU" is optional.
 *
 * @param ifc[out] interface specification to initialize
 * @param arg interface specification to parse
 * @return 0 on success
 */
static int
parse_cmd_arg (struct Interface *ifc,
               const char *arg)
{
  const char *tok;
  char *nspec;

  ifc->mtu = 1500 + sizeof (struct EthernetHeader); /* default in case unspecified */
  tok = strchr (arg, '[');
  if (NULL == tok)
  {
    fprintf (stderr,
             "Error in interface specification: lacks '['");
    return 1;
  }
  ifc->name = strndup (arg,
                       tok - arg);
  arg = tok + 1;
  tok = strchr (arg, ']');
  if (NULL == tok)
  {
    fprintf (stderr,
             "Error in interface specification: lacks ']'");
    return 1;
  }
  nspec = strndup (arg,
                   tok - arg);
  if (0 !=
      parse_network_arg (ifc,
                         nspec))
  {
    free (nspec);
    return 1;
  }
  free (nspec);
  arg = tok + 1;
  if ('=' == arg[0])
  {
    unsigned int mtu;

    if (1 != (sscanf (&arg[1],
                      "%u",
                      &mtu)))
    {
      fprintf (stderr,
               "Error in interface specification: MTU not a number\n");
      return 1;
    }
    if (mtu < 400)
    {
      fprintf (stderr,
               "Error in interface specification: MTU too small\n");
      return 1;
    }
    if (mtu > UINT16_MAX)
    {
      fprintf (stderr,
               "Error in interface specification: MTU too large\n");
      return 1;
    }
    ifc->mtu = mtu + sizeof (struct EthernetHeader);
#if DEBUG
    fprintf (stderr,
             "Interface %s has MTU %u\n",
             ifc->name,
             (unsigned int) ifc->mtu);
#endif
  }
  return 0;
}


/**
 * Handle control message @a cmd.
 *
 * @param cmd text the user entered
 * @param cmd_len length of @a cmd
 */
static void
handle_control (char *cmd,
                size_t cmd_len)
{
  const char *tok;

  cmd[cmd_len - 1] = '\0';
  tok = strtok (cmd,
                " ");
  if (NULL == tok)
    return;
  if (0 == strcasecmp (tok,
                       "arp"))
    process_cmd_arp ();
  else if (0 == strcasecmp (tok,
                            "route"))
    process_cmd_route ();
  else
    fprintf (stderr,
             "Unsupported command `%s'\n",
             tok);
}


/**
 * Handle MAC information @a mac
 *
 * @param ifc_num number of the interface with @a mac
 * @param mac the MAC address at @a ifc_num
 */
static void
handle_mac (uint16_t ifc_num,
            const struct MacAddress *mac)
{
  if (ifc_num > num_ifc)
    abort ();
  gifc[ifc_num - 1].mac = *mac;
}


/**
 * Launches the router.
 *
 * @param argc number of arguments in @a argv
 * @param argv binary name, followed by list of interfaces to switch between
 * @return not really
 */
int
main (int argc,
      char **argv)
{
  struct Interface ifc[argc];

  memset (ifc,
          0,
          sizeof (ifc));
  num_ifc = argc - 1;
  gifc = ifc;
  for (unsigned int i = 1; i<argc; i++)
  {
    struct Interface *p = &ifc[i - 1];

    ifc[i - 1].ifc_num = i;
    if (0 !=
        parse_cmd_arg (p,
                       argv[i]))
      abort ();
  }
  loop (&handle_frame,
        &handle_control,
        &handle_mac);
  for (unsigned int i = 1; i<argc; i++)
    free (ifc[i - 1].name);
  return 0;
}
