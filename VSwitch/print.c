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
 * @file print.c
 * @brief Helper functions for printing and communication with the parent
 * @author Christian Grothoff
 */
#include "glab.h"
#include <stdlib.h>
#include <stdio.h>

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
           size_t buf_size)
{
  const char *cbuf = buf;
  size_t off;

  off = 0;
  while (off < buf_size)
  {
    ssize_t ret;

    ret = write (fd,
                 &cbuf[off],
                 buf_size - off);
    if (ret <= 0)
    {
      fprintf (stderr,
               "Writing %u bytes to %d failed: %s\n",
               (unsigned int) (buf_size - off),
               fd,
               strerror (errno));
      exit (1);
    }
    off += ret;
  }
}


/**
 * Print message to the user by sending to parent.
 *
 * @param fmt format string
 * @param ... arguments for @a fmt
 */
void
print (const char *fmt,
       ...)
{
  char *str;
  va_list ap;

  va_start (ap,
            fmt);
  vasprintf (&str,
             fmt,
             ap);
  va_end (ap);
  {
    size_t slen = strlen (str);
    struct GLAB_MessageHeader hdr = {
      .size = htons (slen + sizeof (struct GLAB_MessageHeader)),
      .type = htons (0)
    };
    char buf[sizeof (hdr) + slen];

    memcpy (buf,
            &hdr,
            sizeof (hdr));
    memcpy (&buf[sizeof(hdr)],
            str,
            slen);
    write_all (STDOUT_FILENO,
               buf,
               sizeof (buf));
  }
  free (str);
}
