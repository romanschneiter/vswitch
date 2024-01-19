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
 * @file vswitch.c
 * @brief Ethernet switch
 * @author Christian Grothoff
 */
#include "glab.h"
#include <stdbool.h>
#include <stdio.h>

/**
 * Maximum number of VLANs supported per interface.
 * (and also by the 802.1Q standard tag).
 */
#define MAX_VLANS 4092

/**
 * Value used to indicate "no VLAN" (or no more VLANs).
 */
#define NO_VLAN (-1)

/**
 * Which VLAN should we assume for untagged frames on
 * interfaces without any specified tag?
 */
#define DEFAULT_VLAN 0

#define ETH_802_1Q_TAG 0x8100

/**
 * Number of entries in the lookup table
 */
#define NBR_ENTRIES 8

/**
 * Interface init number to avoid undefined behaviour if a table entry has not been written yet
 */
#define IF_NO_INIT 65535

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
  uint16_t tag;
};

/**
 * IEEE 802.1Q header.
 */
struct Q
{
  uint16_t tpid; /* must be #ETH_802_1Q_TAG */
  uint16_t tci;
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
   * Number of this interface.
   */
  uint16_t ifc_num;

  /**
   * Name of the network interface, i.e. "eth0".
   */
  char *ifc_name;

  /**
   * Which tagged VLANs does this interface participate in?
   * Array terminated by #NO_VLAN entry.
   */
  int16_t tagged_vlans[MAX_VLANS + 1];

  /**
   * Which untagged VLAN does this interface participate in?
   * #NO_VLAN for none.
   */
  int16_t untagged_vlan;
};

typedef struct LookupTable
{
  struct Interface table[NBR_ENTRIES];
  int nbr_position;  // NBR of rows in table
  int current_position;
} LookupTable;

/**
 * Number of available contexts.
 */
static unsigned int num_ifc;

/**
 * All the contexts.
 */
static struct Interface *gifc;

//Global LookupTable
LookupTable lookupTable;

//Initialize lookupTable in parse frame method
void lookup_table_init(LookupTable *lookupTable){
  const struct MacAddress empty_mac = {{0, 0, 0, 0, 0, 0}};
  for (int i = 0; i < NBR_ENTRIES; i++) {
          for (int j = 0; j < 6; j++) {
              lookupTable->table[i].mac.mac[j] = empty_mac.mac[j];
          }
          lookupTable->table[i].ifc_num = IF_NO_INIT;
      }
  lookupTable->nbr_position = NBR_ENTRIES;
  lookupTable->current_position = 0;
}

/**
 * Is address in LookupTable
 *
 * @param lookupTable: LookupTable
 * @param targetMac: Target Mac address
 * @param found_interface: Pointer to target mac address
 * @return int i = position // -1 = not in table
 */
int search_lookup_table(LookupTable *lookupTable, struct MacAddress *targetMac, struct Interface *found_interface){
   for (int i = 0; i < lookupTable->nbr_position; i++){
        int match = 1;
        //compare Mac at lookupTable Position with complete Mac
        for (int j = 0; j < 6; j++){
            if (lookupTable->table[i].mac.mac[j] != targetMac->mac[j]){
                match = 0;
                break;
            }
        }if (match && lookupTable->table[i].ifc_num != IF_NO_INIT){
            found_interface->ifc_num = lookupTable->table[i].ifc_num;
            for (int j = 0; j < 6; j++){
                found_interface->mac.mac[j] = lookupTable->table[i].mac.mac[j];
            }
            return i;
        }
    }
    return -1;
}

/**
 * Save new entry to the lookup table; also checks if entry is already saved
 *
 * @param lookupTable: Table to save entry to
 * @param new_if: Potentially new interface to learn
 * @return int 0 = learned successful // -1 = already in table
 */
int save_to_table(LookupTable *lookupTable, struct Interface *new_if){
  struct Interface tmp_if;
  int noMac = -1;
  // Check if mac is in table
  int table_pos = search_lookup_table(lookupTable, &new_if->mac, &tmp_if);

  //FOUND
  if (noMac != table_pos){
    // The interface is in table
    if (tmp_if.ifc_num == new_if->ifc_num){
      // interface has still same interface number - no learning
      return -1;
    }else{
      // NBR of interface for this mac has changed - must be changed in table
      lookupTable->table[table_pos].ifc_num = new_if->ifc_num;
      return 0;
    }

  //NOT FOUND
  } else {
    // The MAC is completely new and must be learned
    int current_position = lookupTable->current_position;

    // Copy each field individually
    lookupTable->table[current_position].ifc_num = new_if->ifc_num;
    for (int i = 0; i < 6; i++) {
      lookupTable->table[current_position].mac.mac[i] = new_if->mac.mac[i];
    }

    lookupTable->current_position = (current_position + 1) % lookupTable->nbr_position;
    return 0;
  }
}


/**
 * Forward @a frame to interface @a dst.
 *
 * @param dst target interface to send the frame out on
 * @param frame the frame to forward
 * @param frame_size number of bytes in @a frame
 */
static void
forward_to(struct Interface *dst,
           const void *frame,
           size_t frame_size)
{
  char iob[frame_size + sizeof(struct GLAB_MessageHeader)];
  struct GLAB_MessageHeader hdr;

  hdr.size = htons(sizeof(iob));
  hdr.type = htons(dst->ifc_num);
  memcpy(iob,
         &hdr,
         sizeof(hdr));
  memcpy(&iob[sizeof(hdr)],
         frame,
         frame_size);
  write_all(STDOUT_FILENO,
            iob,
            sizeof(iob));
}

static void
parse_tagged_frame(struct Interface *ifc,
            const void *frame,
            size_t frame_size,
            struct EthernetHeader *header
){

  if (ifc->untagged_vlan != NO_VLAN)
  {
    return;
  }

  // copy frame in byte structure
  uint8_t byte_frame[frame_size];
  memcpy(byte_frame, frame, frame_size);

  // Forward to interface
  for (int i = 0; i < num_ifc; i++)
  {

    // Same interface
    if(gifc[i].ifc_num == ifc->ifc_num){
      continue;
    }

    // Check tagged interfaces
    if (gifc[i].tagged_vlans[0] == ifc->tagged_vlans[0])
    {
      forward_to(&gifc[i], frame, frame_size);
      continue;
    }

    // Check untagged interfaces
     if (gifc[i].untagged_vlan == ifc->tagged_vlans[0])
    {

      // payload without tag = frame - tag (4 byte)
      uint8_t untagged_frame[frame_size - 4]; 
      struct MacAddress untagged_dst = header->dst;
      struct MacAddress untagged_src = header->src;

      // Copy destination and source address. src & dst mac (6 byte each)
      for (int i = 0; i < 6; i++) 
      {
          untagged_frame[i] = ((uint8_t*)&untagged_dst)[i];
          untagged_frame[6 + i] = ((uint8_t*)&untagged_src)[i];
      }

      // Copy payload from source frame to untagged_frame
      // Start after src and dst mac (2 * 6 byte)
      for (int i = 12; i < frame_size; i++) 
      {
          untagged_frame[i] = byte_frame[i+4]; // tag size (4 byte)
      }

      forward_to(&gifc[i], untagged_frame, frame_size - 4);

    }
  }
}

static void
parse_untagged_frame(
            struct Interface *ifc,
            const void *frame,
            size_t frame_size,
            struct EthernetHeader *header
){

  // copy frame in byte structure
  uint8_t byte_frame[frame_size];
  memcpy(byte_frame, frame, frame_size);

  for (int i = 0; i < num_ifc; i++)
  {
    
    // Same interface
    if(gifc[i].ifc_num == ifc->ifc_num)
    {
      continue;
    }

    // Check untagged interfaces
    if (gifc[i].untagged_vlan == ifc->untagged_vlan)
    {
      forward_to(&gifc[i], frame, frame_size);
      continue;
    }

    // Check tagged interfaces
    if (gifc[i].tagged_vlans[0] == ifc->untagged_vlan && gifc[i].ifc_num != ifc->ifc_num)
    {

      uint8_t tagged_frame[frame_size - 12];
      struct MacAddress tagged_dst = header->dst;
      struct MacAddress tagged_src = header->src;
      struct Q tag;
      tag.tpid = htons(0x8100);
      tag.tci = htons(0x001);
     
      // Copy destination and source address. src & dst mac (6 byte each)
      for (int i = 0; i < 6; i++) 
      {
          tagged_frame[i] = ((uint8_t*)&tagged_dst)[i];
          tagged_frame[6 + i] = ((uint8_t*)&tagged_src)[i];
      }

      // Copy Tag
      for (int i = 0; i < 4; i++) {
          tagged_frame[12 + i] = ((uint8_t*)&tag)[i];
      }

      // Copy payload from source frame to tagged_frame
      for (int i = 12; i < frame_size; i++) {
          tagged_frame[i + 4] = byte_frame[i];
      }

      forward_to(&gifc[i], tagged_frame, frame_size + 4);
    }
  }
}


/**
 * Parse and process frame received on @a ifc.
 *
 * @param ifc interface we got the frame on
 * @param frame raw frame data
 * @param frame_size number of bytes in @a frame
 */
static void
parse_frame(struct Interface *ifc,
            const void *frame,
            size_t frame_size)
{

  struct EthernetHeader header;

  //Initialise lookupTable
  if (lookupTable.nbr_position == 0){
    lookup_table_init(&lookupTable);
  }

  if (frame_size < sizeof(header)){
    return;
  }

  //copy frames byte by byte
  const uint8_t *frame_data = (const uint8_t *)frame;
  uint8_t *header_data = (uint8_t *)&header;
  for (size_t i = 0; i < sizeof(header); i++) {
    header_data[i] = frame_data[i];
  }

  struct MacAddress src_addr;
  struct MacAddress dst_addr;
  //copy data from mac byte by byte
  for (size_t i = 0; i < sizeof(struct MacAddress); i++) {
    src_addr.mac[i] = header.src.mac[i];
    dst_addr.mac[i] = header.dst.mac[i];
  }

 // If source broadcast -> throw frame
 // Check if the first bit is 0 -> unicast
  if ((src_addr.mac[0] & 1) !=0){
    return;
  }

  struct Interface lkp_entry = {src_addr, ifc->ifc_num};
  save_to_table(&lookupTable, &lkp_entry);

  struct Interface found_interface;
  int noMacFound = -1;
  // Check for broadcast search for interface if unicast
  if ((dst_addr.mac[0] &1)==0){
    noMacFound = search_lookup_table(&lookupTable, &dst_addr, &found_interface);
  }
  uint16_t ethertype = ntohs(header.tag) & 0xFFFF;
  if (noMacFound == -1){
    if (ethertype == ETH_802_1Q_TAG){
        parse_tagged_frame(ifc,frame,frame_size,&header);
    }else{
      if (ifc->untagged_vlan != NO_VLAN){
        parse_untagged_frame(ifc,frame,frame_size,&header);
      }
    }
  }else{
    forward_to(&found_interface, frame, frame_size);
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
handle_frame(uint16_t interface,
             const void *frame,
             size_t frame_size)
{
  if (interface > num_ifc)
    abort();
  parse_frame(&gifc[interface - 1],
              frame,
              frame_size);
}

/**
 * Handle control message @a cmd.
 *
 * @param cmd text the user entered
 * @param cmd_len length of @a cmd
 */
static void
handle_control(char *cmd,
               size_t cmd_len)
{
  cmd[cmd_len - 1] = '\0';
  fprintf(stderr,
          "Received command `%s' (ignored)\n",
          cmd);
}

/**
 * Handle MAC information @a mac
 *
 * @param ifc_num number of the interface with @a mac
 * @param mac the MAC address at @a ifc_num
 */
static void
handle_mac(uint16_t ifc_num,
           const struct MacAddress *mac)
{
  if (ifc_num > num_ifc)
    abort();
  gifc[ifc_num - 1].mac = *mac;
}

/**
 * Parse tagged interface specification found between @a start
 * and @a end.
 *
 * @param start beginning of tagged specification, with ':'
 * @param end end of tagged specification, should point to ']'
 * @param off interface offset for error reporting
 * @param ifc[out] what to initialize
 * @return 0 on success
 */
static int
parse_tagged(const char *start,
             const char *end,
             int off,
             struct Interface *ifc)
{
  char *spec;
  unsigned int pos;

  if (':' != *start)
  {
    fprintf(stderr,
            "Tagged definition for interface #%d lacks ':'\n",
            off);
    return 1;
  }
  start++;
  spec = strndup(start,
                 end - start);
  if (NULL == spec)
  {
    perror("strndup");
    return 1;
  }
  pos = 0;
  for (const char *tok = strtok(spec,
                                ",");
       NULL != tok;
       tok = strtok(NULL,
                    ","))
  {
    unsigned int tag;

    if (pos == MAX_VLANS)
    {
      fprintf(stderr,
              "Too many VLANs specified for interface #%d\n",
              off);
      free(spec);
      return 1;
    }
    if (1 != sscanf(tok,
                    "%u",
                    &tag))
    {
      fprintf(stderr,
              "Expected number in tagged definition for interface #%d\n",
              off);
      free(spec);
      return 1;
    }
    if (tag > MAX_VLANS)
    {
      fprintf(stderr,
              "%u is too large for a 802.1Q VLAN ID (on interface #%d)\n",
              tag,
              off);
      free(spec);
      return 1;
    }
    ifc->tagged_vlans[pos++] = (int16_t)tag;
  }
  ifc->tagged_vlans[pos] = NO_VLAN;
  free(spec);
  return 0;
}

/**
 * Parse untagged interface specification found between @a start
 * and @a end.
 *
 * @param start beginning of tagged specification, with ':'
 * @param end end of tagged specification, should point to ']'
 * @param off interface offset for error reporting
 * @param ifc[out] what to initialize
 * @return 0 on success
 */
static int
parse_untagged(const char *start,
               const char *end,
               int off,
               struct Interface *ifc)
{
  char *spec;
  unsigned int tag;

  if (':' != *start)
  {
    fprintf(stderr,
            "Untagged definition for interface #%d lacks ':'\n",
            off);
    return 1;
  }
  start++;
  spec = strndup(start,
                 end - start);
  if (NULL == spec)
  {
    perror("strndup");
    return 1;
  }
  if (1 != sscanf(spec,
                  "%u",
                  &tag))
  {
    fprintf(stderr,
            "Expected number in untagged definition for interface #%d\n",
            off);
    free(spec);
    return 1;
  }
  if (tag > MAX_VLANS)
  {
    fprintf(stderr,
            "%u is too large for a 802.1Q VLAN ID (on interface #%d)\n",
            tag,
            off);
    free(spec);
    return 1;
  }
  ifc->untagged_vlan = (int16_t)tag;
  free(spec);
  return 0;
}

/**
 * Parse command-line argument with interface specification.
 *
 * @param arg command-line argument
 * @param off offset of @a arg for error reporting
 * @param ifc interface to initialize (ifc_name, tagged_vlans and untagged_vlan).
 * @return 0 on success
 */
static int
parse_vlan_args(const char *arg,
                int off,
                struct Interface *ifc)
{
  const char *openbracket;
  const char *closebracket;

  ifc->tagged_vlans[0] = NO_VLAN;
  ifc->untagged_vlan = NO_VLAN;

  openbracket = strchr(arg,
                       (unsigned char)'[');

  if (NULL == openbracket)
  {
    ifc->ifc_name = strdup(arg);
    if (NULL == ifc->ifc_name)
    {
      perror("strdup");
      return 1;
    }
    ifc->untagged_vlan = DEFAULT_VLAN;
    return 0;
  }

  ifc->ifc_name = strndup(arg,
                          openbracket - arg);
  if (NULL == ifc->ifc_name)
  {
    perror("strndup");
    return 1;
  }
  openbracket++;
  closebracket = strchr(openbracket,
                        (unsigned char)']');
  if (NULL == closebracket)
  {
    fprintf(stderr,
            "Interface definition #%d includes '[' but lacks ']'\n",
            off);
    return 1;
  }
  switch (*openbracket)
  {
  case 'T':
    return parse_tagged(openbracket + 1,
                        closebracket,
                        off,
                        ifc);
    break;
  case 'U':
    return parse_untagged(openbracket + 1,
                          closebracket,
                          off,
                          ifc);
    break;
  default:
    fprintf(stderr,
            "Unsupported tagged/untagged specification `%c' in interface definition #%d\n",
            *openbracket,
            off);
    return 1;
  }
}

/**
 * Launches the vswitch.
 *
 * @param argc number of arguments in @a argv
 * @param argv binary name, followed by list of interfaces to switch between
 * @return not really
 */
int main(int argc,
         char **argv)
{
  struct Interface ifc[argc - 1];

  (void)print;

  memset(ifc, 0, sizeof(ifc));

  num_ifc = argc - 1;
  gifc = ifc;

  for (unsigned int i = 1; i < argc; i++)
  {
    ifc[i - 1].ifc_num = i;
    if (0 !=
        parse_vlan_args(argv[i],
                        i,
                        &ifc[i - 1]))
      return 1;
  }

  loop(&handle_frame, &handle_control, &handle_mac);
  return 0;
}