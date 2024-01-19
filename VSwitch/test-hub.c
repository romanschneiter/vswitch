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
 * @file test-hub.c
 * @brief Testcase for the 'hub'.  Must be linked with harness.c.
 * @author Christian Grothoff
 */
#include "harness.h"

/**
 * Set to 1 to enable debug statments.
 */
#define DEBUG 0


/**
 * Run test with @a prog.  Check that with just 1 interface, the hub does nothing.
 *
 * @param prog command to test
 * @return 0 on success, non-zero on failure
 */
static int
test_bc0 (const char *prog)
{
  char my_frame[1400];
  int
  send_frame ()
  {
    tsend (1,
           my_frame,
           sizeof (my_frame));
    return 0;
  };

  char *argv[] = {
    (char *) prog,
    "eth0",
    NULL
  };
  struct Command cmd[] = {
    { "send frame", &send_frame },
    { "expect nothing", &expect_silence },
    { NULL }
  };

  for (unsigned int i = 0; i<sizeof (my_frame); i++)
    my_frame[i] = random (); /* completely randomize frame */
  return meta (cmd,
               (sizeof (argv) / sizeof (char *)) - 1,
               argv);
}


/**
 * Run test with @a prog.  Simple forwarding of one frame to all
 * other interfaces.
 *
 * @param prog command to test
 * @return 0 on success, non-zero on failure
 */
static int
test_bc1 (const char *prog)
{
  char my_frame[1400];
  int
  send_frame ()
  {
    tsend (1,
           my_frame,
           sizeof (my_frame));
    return 0;
  };
  int
  expect_broadcast ()
  {
    uint64_t ifcs = (1 << 1) | (1 << 2); /* eth1 and eth2 */

    return trecv (1, /* expect *two* replies */
                  &expect_multicast,
                  &ifcs,
                  my_frame,
                  sizeof (my_frame),
                  UINT16_MAX /* ignored */);
  };

  char *argv[] = {
    (char *) prog,
    "eth0",
    "eth1",
    "eth2",
    NULL
  };
  struct Command cmd[] = {
    { "send frame", &send_frame },
    { "check broadcast", &expect_broadcast },
    { "end", &expect_silence },
    { NULL }
  };

  for (unsigned int i = 0; i<sizeof (my_frame); i++)
    my_frame[i] = random (); /* completely randomize frame */
  return meta (cmd,
               (sizeof (argv) / sizeof (char *)) - 1,
               argv);
}


/**
 * Run test with @a prog.  Forward frames from all interfaces to all
 * other interfaces.
 *
 * @param prog command to test
 * @return 0 on success, non-zero on failure
 */
static int
test_bc123 (const char *prog)
{
  char my_frame[1400];
  unsigned int src = 1;
  uint64_t ifcs = 0;
  int
  send_frame ()
  {
    tsend (src,
           my_frame,
           sizeof (my_frame));
    ifcs = (1 << 0) | (1 << 1) | (1 << 2); /* eth0-eth2 */
    ifcs -= (1 << (src - 1));
    src++;
    return 0;
  };
  int
  expect_broadcast ()
  {
    return trecv (1, /* expect *two* replies */
                  &expect_multicast,
                  &ifcs,
                  my_frame,
                  sizeof (my_frame),
                  UINT16_MAX /* ignored */);
  };

  char *argv[] = {
    (char *) prog,
    "eth0",
    "eth1",
    "eth2",
    NULL
  };
  struct Command cmd[] = {
    { "send frame", &send_frame },
    { "check broadcast", &expect_broadcast },
    { "send frame", &send_frame },
    { "check broadcast", &expect_broadcast },
    { "send frame", &send_frame },
    { "check broadcast", &expect_broadcast },
    { "end", &expect_silence },
    { NULL }
  };

  for (unsigned int i = 0; i<sizeof (my_frame); i++)
    my_frame[i] = random (); /* completely randomize frame */
  return meta (cmd,
               (sizeof (argv) / sizeof (char *)) - 1,
               argv);
}


/**
 * Run test with @a prog.  Forward large frame.
 *
 * @param prog command to test
 * @return 0 on success, non-zero on failure
 */
static int
test_bc_large (const char *prog)
{
  char my_frame[14000];
  int
  send_frame ()
  {
    tsend (1,
           my_frame,
           sizeof (my_frame));
    return 0;
  };
  int
  expect_broadcast ()
  {
    uint64_t ifcs = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4); /* eth1-eth4 */

    return trecv (3, /* expect *four* replies */
                  &expect_multicast,
                  &ifcs,
                  my_frame,
                  sizeof (my_frame),
                  UINT16_MAX /* ignored */);
  };

  char *argv[] = {
    (char *) prog,
    "eth0",
    "eth1",
    "eth2",
    "eth3",
    "eth4",
    NULL
  };
  struct Command cmd[] = {
    { "send frame", &send_frame },
    { "check broadcast", &expect_broadcast },
    { "end", &expect_silence },
    { NULL }
  };

  for (unsigned int i = 0; i<sizeof (my_frame); i++)
    my_frame[i] = random (); /* completely randomize frame */
  return meta (cmd,
               (sizeof (argv) / sizeof (char *)) - 1,
               argv);
}


/**
 * Call with path to the hub program to test.
 */
int
main (int argc,
      char **argv)
{
  unsigned int grade = 0;
  unsigned int possible = 0;
  struct Test
  {
    const char *name;
    int (*fun)(const char *arg);
  } tests[] = {
    { "no-cast (one interface)", &test_bc0 },
    { "normal broadcast", &test_bc1 },
    { "back and forth", &test_bc123 },
    { "large frame", &test_bc_large },
    { NULL, NULL }
  };

  if (argc != 2)
  {
    fprintf (stderr,
             "Call with HUB program to test as 1st argument!\n");
    return 1;
  }
  for (unsigned int i = 0; NULL != tests[i].fun; i++)
  {
    if (0 == tests[i].fun (argv[1]))
      grade++;
    else
      fprintf (stdout,
               "Failed test `%s'\n",
               tests[i].name);
    possible++;
  }
  fprintf (stdout,
           "Final grade: %u/%u\n",
           grade,
           possible);
  return 0;
}
