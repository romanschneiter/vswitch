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
 * @file loop.c
 * @brief Sample implementation of the main loop for interacting with the parent
 * @author Christian Grothoff
 */
#include "glab.h"
#include <stdlib.h>
#include <stdio.h>

/**
 * Sample main loop.  Reads packets from STDIN_FILENO
 * and calls handle_mac(), handle_control() or handle_frame()
 * on each depending on the type.
 */
void
loop (FrameHandler fh,
      ControlHandler ch,
      MacHandler mh)
{
  char buf[UINT16_MAX];
  size_t off;
  ssize_t ret;
  int have_mac;

  off = 0;
  have_mac = 0;
  while (-1 != (ret = read (STDIN_FILENO,
                            &buf[off],
                            sizeof (buf) - off)))
  {
    struct GLAB_MessageHeader hdr;
    uint16_t size;

    if (0 >= ret)
      break;
    off += ret;
    while (off > sizeof (struct GLAB_MessageHeader))
    {
      memcpy (&hdr,
              buf,
              sizeof (hdr));
      size = ntohs (hdr.size);
      if (off < size)
        break;
      if (size < sizeof (struct GLAB_MessageHeader))
        abort ();
      switch (ntohs (hdr.type))
      {
      case 0: /* control */
        if (0 == have_mac)
        {
          for (unsigned int i = 0; i<(size - sizeof (hdr)) / sizeof (struct
                                                                     MacAddress);
               i++)
          {
            struct MacAddress mac;

            memcpy (&mac,
                    &buf[sizeof (hdr) + i * sizeof (struct MacAddress)],
                    sizeof (struct MacAddress));
            mh (i + 1,
                &mac);
          }
          have_mac = 1;
        }
        else
        {
          ch (&buf[sizeof (hdr)],
              size - sizeof (hdr));
        }
        break;
      default:
        fh (ntohs (hdr.type),
            (const void *) &buf[sizeof (hdr)],
            size - sizeof (hdr));
        break;
      }
      memmove (buf,
               &buf[size],
               off - size);
      off -= size;
    }
  }
}
