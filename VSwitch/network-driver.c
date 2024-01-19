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
 * @file network-driver.c
 * @brief Opens a set of virtual network-interfaces,
 * sends data received on the if to stdout, sends data received on stdin to the
 * interfaces
 * @author Philipp Tölke
 * @author Christian Grothoff
 */
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/llc.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <linux/if_packet.h>
#include "glab.h"


/**
 * Should we print (interesting|debug) messages that can happen during
 * normal operation?
 */
#define DEBUG 0

/**
 * Maximum size of a message.
 */
#define MAX_SIZE (65536 + sizeof (struct GLAB_MessageHeader))

/**
 * Should we filter packets by MAC and only pass on packets for
 * this interface (or multicast)?
 */
#define FILTER_BY_MAC 0

/**
 * Where is the VLAN tag in the Ethernet frame?
 */
#define VLAN_OFFSET (2 * MAC_ADDR_SIZE)

struct vlan_tag
{
  uint16_t vlan_tpid;     /* ETH_P_8021Q */
  uint16_t vlan_tci;    /* VLAN TCI */
};

/**
 * Check if VLAN TCI provided is valid.
 */
#define VLAN_VALID(hdr, hv) ((hv)->tp_vlan_tci != 0 || ((hdr)->tp_status \
                                                        & TP_STATUS_VLAN_VALID))

/**
 * Compute the TPID given the AUX Data.
 */
#define VLAN_TPID(hdr, hv) (((hv)->tp_vlan_tpid || ((hdr)->tp_status \
                                                    & TP_STATUS_VLAN_TPID_VALID)) \
  ? (hv)->tp_vlan_tpid : ETH_P_8021Q)


#ifndef _LINUX_IN6_H
/**
 * This is in linux/include/net/ipv6.h, but not always exported...
 */
struct in6_ifreq
{
  struct in6_addr ifr6_addr;
  uint32_t ifr6_prefixlen;
  unsigned int ifr6_ifindex;
};
#endif

#define MAC_ADDR_SIZE 6

#define MAX(a,b) ((a) > (b))?(a):(b)

/**
 * Information about an interface.
 */
struct Interface
{

  /**
   * Set to our MAC address.
   */
  uint8_t my_mac[MAC_ADDR_SIZE];

  /**
   * File descriptor for the interface.
   */
  int fd;

  /**
   * The buffer filled by reading from @e fd. Plus some extra
   * space for VLAN tag synthesis.
   */
  unsigned char buftun[MAX_SIZE + sizeof (struct vlan_tag)];

  /**
   * Current offset into @e buftun for writing to #child_stdin.
   */
  unsigned char *buftun_off;

  /**
   * Number of bytes in @e buftun (offset for reading more),
   * may start at an offset!
   */
  size_t buftun_size;

  /**
   * Number of bytes READY in @e buftun_off for current ready message.
   * Equals @e buftun_size for normal interfaces, but may differ for
   * control (cmd_line).
   */
  size_t buftun_end;

  /**
   * index of interface
   */
  struct ifreq if_idx;

};


/**
 * STDIN of child process (to be written to).
 */
static int child_stdin;

/**
 * STDOUT of child process (to be read from).
 */
static int child_stdout;

/**
 * Child PID
 */
static pid_t chld;


/**
 * Creates a tun-interface called dev;
 *
 * @param dev is asumed to point to a char[IFNAMSIZ]
 *        if *dev == '\\0', uses the name supplied by the kernel;
 * @param ifc[out] initialized interface struct
 * @return 0 on success, or -1 on error
 */
static int
init_tun (char *dev,
          struct Interface *ifc)
{
  struct ifreq ifr;
  int fd;
  struct ifreq if_mac;
  struct ifreq ifopts;
  struct ifreq so;
  struct ethtool_value ev;

  if (NULL == dev)
  {
    errno = EINVAL;
    return -1;
  }

  if (-1 == (fd = socket (AF_PACKET,
                          SOCK_RAW,
                          htons (ETH_P_ALL))))
  {
    fprintf (stderr,
             "Error opening socket: %s\n",
             strerror (errno));
    return -1;
  }

  if (fd >= FD_SETSIZE)
  {
    fprintf (stderr,
             "File descriptor to large: %d",
             fd);
    (void) close (fd);
    return -1;
  }
  /* only take traffic of 'dev' */
  if (0 !=
      setsockopt (fd,
                  SOL_SOCKET,
                  SO_BINDTODEVICE,
                  dev,
                  strlen (dev) + 1))
  {
    fprintf (stderr,
             "Failed to limit myself to `%s' for inbound traffic: %s\n",
             dev,
             strerror (errno));
    (void) close (fd);
    return -1;
  }

  /* Enable grabbing auxiliary data, including VLAN information */
  {
    int val = 1;

    if (0 != setsockopt (fd,
                         SOL_PACKET,
                         PACKET_AUXDATA,
                         &val,
                         sizeof(val)))
    {
      fprintf (stderr,
               "Failed to activate PACKET_AUXDATA: %s\n",
               strerror (errno));
      (void) close (fd);
      return -1;
    }
  }

  memset (&ifr,
          0,
          sizeof (ifr));

  /* Get the index of the interface to send on */
  memset (&ifc->if_idx,
          0,
          sizeof (struct ifreq));
  strncpy (ifc->if_idx.ifr_name,
           dev,
           IFNAMSIZ - 1);
  if (ioctl (fd,
             SIOCGIFINDEX,
             &ifc->if_idx) < 0)
  {
    fprintf (stderr,
             "Could not use interface `%s': %s",
             dev,
             strerror (errno));
    (void) close (fd);
    return -1;
  }
  /* Get the MAC address of the interface to send on */
  memset (&if_mac,
          0,
          sizeof(struct ifreq));
  strncpy (if_mac.ifr_name,
           dev,
           IFNAMSIZ - 1);
  if (0 > ioctl (fd,
                 SIOCGIFHWADDR,
                 &if_mac))
  {
    fprintf (stderr,
             "Could not obtain MAC of interface `%s': %s",
             dev,
             strerror (errno));
    (void) close (fd);
    return -1;
  }
  memcpy (&ifc->my_mac,
          &if_mac.ifr_hwaddr.sa_data,
          MAC_ADDR_SIZE);

  strncpy (ifopts.ifr_name,
           dev,
           IFNAMSIZ - 1);
  if (0 > ioctl (fd,
                 SIOCGIFFLAGS,
                 &ifopts))
  {
    fprintf (stderr,
             "Could not obtain flags of interface `%s': %s",
             dev,
             strerror (errno));
    (void) close (fd);
    return -1;
  }
  ifopts.ifr_flags |= IFF_PROMISC;
  if (0 > ioctl (fd,
                 SIOCSIFFLAGS,
                 &ifopts))
  {
    fprintf (stderr,
             "Could not set flags of interface `%s': %s",
             dev,
             strerror (errno));
    (void) close (fd);
    return -1;
  }

  /* Disable segmentation offloads:
     - TSO TCP Segmentation Offload
     - GSO Generic Segmentation Offload
     - GRO Generic Receive Offload
     (as our clients must not be expected to deal with frames exceeding the MTU) */
  const uint32_t ethtool_cmd[] = { ETHTOOL_STSO, ETHTOOL_SGSO, ETHTOOL_SGRO };
  for (int i = 0; i<sizeof(ethtool_cmd) / sizeof(uint32_t); i++)
  {
    ev.cmd = ethtool_cmd[i];
    ev.data = 0;
    memset (&so,
            0,
            sizeof (so));
    strncpy (so.ifr_name,
             dev,
             IFNAMSIZ - 1);
    so.ifr_data = (char*) &ev;
    if (0 > ioctl (fd,
                   SIOCETHTOOL,
                   &so))
    {
      fprintf (stderr,
               "Could not disable offload %u on interface `%s': %s",
               ethtool_cmd[i],
               dev,
               strerror (errno));
      (void) close (fd);
      return -1;
    }
  }

  ifc->fd = fd;
  return 0;
}


/**
 * Start forwarding to and from the tunnel.
 *
 * @param gifc array of interfaces
 * @param gifc_len length of @a gifc
 */
static void
run (struct Interface *gifc,
     int gifc_len)
{
  /*
   * The buffer filled by reading from child's stdout, to be passed to some fd
   */
  unsigned char bufin[MAX_SIZE];
  /* bytes left to write from 'bufin_write' to 'current_write' */
  ssize_t bufin_write_left = 0;
  /* read stream offset in 'bufin' */
  size_t bufin_rpos = 0;
  /* write stream offset into 'bufin' */
  unsigned char *bufin_write_off = NULL;
  /* write refers to reading from child's stdout, writing to index 'current_write' */
  struct Interface *current_write = NULL;
  fd_set fds_w;
  fd_set fds_r;
  int fmax;
  /* We treat command-line input as a special 'network interface' */
  struct Interface cmd_line;

  /* read refers to reading from fd, currently writing to child's stdin */
  struct Interface *current_read = NULL;

  memset (&cmd_line,
          0,
          sizeof (cmd_line));
  /* Leave room for header! */
  cmd_line.buftun_size = sizeof (struct GLAB_MessageHeader);
  while (1)
  {
    fmax = -1;
    FD_ZERO (&fds_w);
    FD_ZERO (&fds_r);

    /* try to write to child */
    if (NULL != current_read)
    {
      /*
       * We have a job pending to write to Child's STDIN.
       */
      FD_SET (child_stdin,
              &fds_w);
      fmax = MAX (fmax,
                  child_stdin);
    }

    /* try to write to TUN device */
    if (NULL != current_write)
    {
      /*
       * We have a job pending to write to a TUN.
       */
      FD_SET (current_write->fd,
              &fds_w);
      fmax = MAX (fmax,
                  current_write->fd);
    }

    /* try to read from interfaces */
    for (unsigned int i = 0; i<gifc_len; i++)
    {
      struct Interface *ifc = &gifc[i];

      if (0 == ifc->buftun_size)
      {
        /*
         * We are able to read more into our read buffer.
         */
        FD_SET (ifc->fd,
                &fds_r);
        fmax = MAX (fmax,
                    ifc->fd);
      }
    }

    /* try to read from child */
    if (bufin_rpos < MAX_SIZE)
    {
      /*
       * We are able to read more into our read buffer.
       */
      FD_SET (child_stdout,
              &fds_r);
      fmax = MAX (fmax,
                  child_stdout);
    }

    /* Also try to read from command-line */
    if (cmd_line.buftun_size < MAX_SIZE - sizeof (struct GLAB_MessageHeader))
    {
      FD_SET (STDIN_FILENO,
              &fds_r);
      fmax = MAX (fmax,
                  STDIN_FILENO);
    }

    int r = select (fmax + 1,
                    &fds_r,
                    &fds_w,
                    NULL,
                    NULL);
    if (-1 == r)
    {
      if (EINTR == errno)
        continue;
      fprintf (stderr,
               "select failed: %s\n",
               strerror (errno));
      return;
    }

    if (0 == r)
      continue;

    /* Read from command-line */
    if (FD_ISSET (STDIN_FILENO,
                  &fds_r))
    {
      ssize_t ret = read (STDIN_FILENO,
                          &cmd_line.buftun[cmd_line.buftun_size],
                          MAX_SIZE - sizeof (struct GLAB_MessageHeader)
                          - cmd_line.buftun_size);
      if (0 >= ret)
        return;
      cmd_line.buftun_size += ret;
    }

    /* check if child is ready for reading (so we can write to it) */
    if ( (FD_ISSET (child_stdin,
                    &fds_w)) &&
         (NULL != current_read) )
    {
      ssize_t written = write (child_stdin,
                               current_read->buftun_off,
                               current_read->buftun_end);
      if (-1 == written)
      {
        fprintf (stderr,
                 "write-error to stdout: %s\n",
                 strerror (errno));
        return;
      }
      if (0 == written)
      {
        fprintf (stderr,
                 "write returned 0!?\n");
        return;
      }
      current_read->buftun_end -= written;
      current_read->buftun_off += written;
      if (0 == current_read->buftun_end)
      {
        size_t total_w = (current_read->buftun_off - current_read->buftun);
        size_t move_off = 0;

        if (current_read == &cmd_line)
        {
          /* don't count the header, preserve space for it! */
          total_w -= sizeof (struct GLAB_MessageHeader);
          move_off += sizeof (struct GLAB_MessageHeader);
        }
        memmove (&current_read->buftun[move_off],
                 current_read->buftun_off,
                 current_read->buftun_size - total_w);
        current_read->buftun_size -= total_w;
        current_read->buftun_off = NULL;
        current_read = NULL;     /* we're done with forwarding from this ifc */
      }
    }

    /* Forward child's stream to network interface, if possible */
    if ( (NULL != current_write) &&
         (FD_ISSET (current_write->fd,
                    &fds_w)) )
    {
      struct sockaddr_ll sadr_ll;

      sadr_ll.sll_ifindex = current_write->if_idx.ifr_ifindex;
      sadr_ll.sll_halen = MAC_ADDR_SIZE;
      memcpy (&sadr_ll.sll_addr[0],
              bufin_write_off,
              sizeof (struct MacAddress));

      ssize_t written = sendto (current_write->fd,
                                bufin_write_off,
                                bufin_write_left,
                                0,
                                (const struct sockaddr *) &sadr_ll,
                                sizeof (struct sockaddr_ll));

      if (-1 == written)
      {
        fprintf (stderr,
                 "write-error to tun: %s\n",
                 strerror (errno));
        return;
      }
      if (0 == written)
      {
        fprintf (stderr,
                 "write returned 0!?\n");
        return;
      }
      bufin_write_left -= written;
      bufin_write_off += written;
      if (0 == bufin_write_left)
      {
        memmove (bufin,
                 bufin_write_off,
                 bufin_rpos - (bufin_write_off - bufin));
        bufin_rpos -= (bufin_write_off - bufin);
        bufin_write_off = NULL;
        current_write = NULL;     /* done! */
      }
    }

    if (NULL == current_read)
    {
      unsigned char *nl;

      nl = memchr (&cmd_line.buftun[sizeof (struct GLAB_MessageHeader)],
                   '\n',
                   cmd_line.buftun_size - sizeof (struct GLAB_MessageHeader));
      if (NULL != nl)
      {
        struct GLAB_MessageHeader hd;

        hd.type = htons (0);
        hd.size = htons (1 + nl - cmd_line.buftun);
        memcpy (&cmd_line.buftun,
                &hd,
                sizeof (hd));
        current_read = &cmd_line;
        current_read->buftun_end = 1 + nl - cmd_line.buftun;
        current_read->buftun_off = cmd_line.buftun;
      }
    }

    /* Read from child's stream for forwarding to network, if possible */
    if (FD_ISSET (child_stdout,
                  &fds_r))
    {
      ssize_t ret;

      ret = read (child_stdout,
                  &bufin[bufin_rpos],
                  MAX_SIZE - bufin_rpos);
      if (-1 == ret)
      {
        fprintf (stderr,
                 "read-error: %s\n",
                 strerror (errno));
        return;
      }
      if (0 == ret)
      {
        fprintf (stderr,
                 "EOF from child\n");
        return;
      }
      bufin_rpos += ret;
    }

    /* Handle data in 'bufin' (from child's stdout), if complete and possible */
rbuf_again:
    if ( (NULL == current_write) &&
         (bufin_rpos >= sizeof (struct GLAB_MessageHeader)) )
    {
      struct GLAB_MessageHeader hd;
      uint16_t s;

      memcpy (&hd,
              bufin,
              sizeof (hd));
      s = ntohs (hd.size);
      if (s <= bufin_rpos)
      {
        uint16_t n = ntohs (hd.type);

        if (0 == n)
        {
          fprintf (stdout,
                   "%.*s",
                   (int) (s - sizeof (hd)),
                   &bufin[sizeof(hd)]);
          fflush (stdout);
          memmove (bufin,
                   &bufin[s],
                   bufin_rpos - s);
          bufin_rpos -= s;
          goto rbuf_again;       /* stdout doesn't wait in select() */
        }
        if (n > gifc_len)
        {
          fprintf (stderr,
                   "Invalid interface %u specified in message\n",
                   (unsigned int) n);
          return;
        }
        /* Got a complete message! */
        current_write = &gifc[n - 1];
        bufin_write_left = s - sizeof (hd);
        bufin_write_off = &bufin[sizeof (hd)];
      }
    }

    /* read from network interfaces, if possible */
    for (unsigned int i = 0; i<gifc_len; i++)
    {
      struct Interface *ifc = &gifc[i];

      if (FD_ISSET (ifc->fd,
                    &fds_r) &&
          (0 == ifc->buftun_size))
      {
        struct GLAB_MessageHeader hdr;
        ssize_t ret;
        struct sockaddr_ll sadr_ll;
        struct cmsghdr *cmsg;
        union
        {
          struct cmsghdr cmsg;
          char buf[CMSG_SPACE (sizeof (struct tpacket_auxdata))];
        } cmsg_buf;
        struct msghdr msg;
        struct iovec iov = {
          .iov_base = ifc->buftun + sizeof (struct GLAB_MessageHeader),
          .iov_len = MAX_SIZE
        };

        memset (&msg,
                0,
                sizeof (msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_name = &sadr_ll;
        msg.msg_namelen = sizeof (sadr_ll);
        msg.msg_control = &cmsg_buf;
        msg.msg_controllen = sizeof (cmsg_buf);
        memset (iov.iov_base,
                0,
                MAX_SIZE);
        ret = recvmsg (ifc->fd,
                       &msg,
                       0 /* flags */);
        if (-1 == ret)
        {
          fprintf (stderr,
                   "read-error: %s\n",
                   strerror (errno));
          return;
        }
        if (sadr_ll.sll_ifindex != ifc->if_idx.ifr_ifindex)
        {
#if DEBUG
          fprintf (stderr,
                   "recvfrom for different interface, discarding\n");
#endif
          continue;
        }
        if (0 == ret)
        {
          fprintf (stderr,
                   "EOF on tun\n");
          return;
        }

        for (cmsg = CMSG_FIRSTHDR (&msg);
             NULL != cmsg;
             cmsg = CMSG_NXTHDR (&msg, cmsg))
        {
          struct tpacket_auxdata *aux;
          struct vlan_tag *tag;

          if ((cmsg->cmsg_len < CMSG_LEN (sizeof(struct tpacket_auxdata))) ||
              (cmsg->cmsg_level != SOL_PACKET) ||
              (cmsg->cmsg_type != PACKET_AUXDATA) )
          {
            /*
             * This isn't a PACKET_AUXDATA auxiliary
             * data item.
             */
            continue;
          }

          aux = (struct tpacket_auxdata *) CMSG_DATA (cmsg);
          if (! VLAN_VALID (aux, aux))
          {
            /*
             * There is no VLAN information in the
             * auxiliary data.
             */
            continue;
          }

          if (ret < (size_t) VLAN_OFFSET)
            break;     /* awkward... */
          tag = iov.iov_base + VLAN_OFFSET;
          memmove (&tag[1],
                   tag,
                   ret - VLAN_OFFSET);
          tag->vlan_tpid = htons (VLAN_TPID (aux, aux));
          tag->vlan_tci = htons (aux->tp_vlan_tci);
          ret += sizeof (*tag);
        }

        ifc->buftun_size = (size_t) ret + sizeof (struct GLAB_MessageHeader);
        hdr.type = htons (i + 1);
        hdr.size = htons (ifc->buftun_size);
        memcpy (ifc->buftun,
                &hdr,
                sizeof (hdr));
        if (FILTER_BY_MAC &&
            (0 != memcmp (ifc->my_mac,
                          ifc->buftun + sizeof (struct GLAB_MessageHeader),
                          sizeof (ifc->my_mac))) &&
            (0 == (0x80 & ifc->buftun[sizeof (struct GLAB_MessageHeader)])) )
        {
          /* Not unicast to me and not multicast, ignore! */
          ifc->buftun_size = 0;
        }
        else
        {
          /* read to send message */
          ifc->buftun_end = ifc->buftun_size;
        }
      }

      /* If child is ready for another packet, and this interface is ready,
         queue the job */
      if ( (NULL == current_read) &&
           (0 != ifc->buftun_size) )
      {
        current_read = ifc;
        current_read->buftun_off = ifc->buftun;
      }
    }   /* end for(ifc) */
  }
}


/**
 * Open network interfaces and pass traffic from/to child process.
 *
 * @param argc number of arguments in @a argv
 * @param argv 0: binary name (network-driver)
 *             1..n: network interface name (e.g. eth0)
 *             n+1: "-"
 *             n+2: child program to launch
 */
int
main (int argc,
      char **argv)
{
  struct Interface *gifc;
  int global_ret;
  int end;

  for (end = 1; NULL != argv[end]; end++)
    if (0 == strcmp ("-",
                     argv[end]))
      break;
  if (2 > end)
  {
    fprintf (stderr,
             "Fatal: must supply network interface names!\n");
    return 1;
  }
  if (end == argc)
  {
    fprintf (stderr,
             "Fatal: must supply child process to launch!\n");
    return 1;
  }

  /* Launch child process */
  {
    int cin[2];
    int cout[2];

    if (0 != pipe (cin))
    {
      perror ("pipe");
      return 1;
    }
    if (0 != pipe (cout))
    {
      perror ("pipe");
      return 1;
    }
    chld = fork ();
    if (-1 == chld)
    {
      perror ("fork");
      return 1;
    }
    if (0 == chld)
    {
      close (STDIN_FILENO);
      close (STDOUT_FILENO);
      close (cin[1]);
      close (cout[0]);
      if (-1 == dup2 (cin[0],
                      STDIN_FILENO))
      {
        perror ("dup2");
        exit (1);
      }
      if (-1 == dup2 (cout[1],
                      STDOUT_FILENO))
      {
        perror ("dup2");
        exit (1);
      }
      execvp (argv[end + 1],
              &argv[end + 1]);
      perror ("execvp");
      exit (1);
    }
    close (cin[0]);
    close (cout[1]);
    child_stdin = cin[1];
    child_stdout = cout[0];
  } /* end launch child */

  gifc = calloc (end - 1,
                 sizeof (struct Interface));
  if (NULL == gifc)
    abort ();
  for (unsigned int i = 1; i<end; i++)
    gifc[i - 1].fd = -1;
  for (unsigned int i = 1; i<end; i++)
  {
    struct Interface *ifc = &gifc[i - 1];
    char dev[IFNAMSIZ];

    strncpy (dev,
             argv[i],
             IFNAMSIZ);
    dev[IFNAMSIZ - 1] = '\0';
    if (-1 == init_tun (dev,
                        ifc))
    {
      fprintf (stderr,
               "Fatal: could not initialize interface `%s'\n",
               dev);
      global_ret = 4;
      goto cleanup;
    }
  }

  {
    struct GLAB_MessageHeader gh;
    char *mbuf;
    size_t size;

    size = sizeof (struct GLAB_MessageHeader) + (end - 1) * MAC_ADDR_SIZE;
    mbuf = malloc (size);
    if (NULL == mbuf)
      abort ();
    gh.size = htons  (size);
    gh.type = htons (0);
    memcpy (mbuf,
            &gh,
            sizeof (gh));
    for (unsigned int i = 1; i<end; i++)
      memcpy (&mbuf[sizeof (struct GLAB_MessageHeader) + (i - 1)
                    * MAC_ADDR_SIZE],
              gifc[i - 1].my_mac,
              MAC_ADDR_SIZE);
    if (size !=
        write (child_stdin,
               mbuf,
               size))
    {
      fprintf (stderr,
               "Failed to send my MACs to application: %s",
               strerror (errno));
      free (mbuf);
      global_ret = 4;
      goto cleanup;
    }
    free (mbuf);
  }

  {
    uid_t uid = getuid ();
#ifdef HAVE_SETRESUID
    if (0 != setresuid (uid,
                        uid,
                        uid))
    {
      fprintf (stderr,
               "Failed to setresuid: %s\n",
               strerror (errno));
      global_ret = 2;
      goto cleanup;
    }
#else
    if (0 != (setuid (uid) | seteuid (uid)))
    {
      fprintf (stderr,
               "Failed to setuid: %s\n",
               strerror (errno));
      global_ret = 2;
      goto cleanup;
    }
#endif
  }

  if (SIG_ERR ==
      signal (SIGPIPE,
              SIG_IGN))
  {
    fprintf (stderr,
             "Failed to protect against SIGPIPE: %s\n",
             strerror (errno));
    /* no exit, we might as well die with SIGPIPE should it ever happen */
  }
  fprintf (stderr,
           "Starting main loop\n");
  run (gifc,
       end - 1);
  kill (chld,
        SIGKILL);
  global_ret = 0;
cleanup:
  for (unsigned int i = 1; i<end; i++)
    if (-1 != gifc[i - 1].fd)
      close (gifc[i - 1].fd);
  free (gifc);
  return global_ret;
}
