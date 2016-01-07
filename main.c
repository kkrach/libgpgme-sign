/* main.c  - Program to perform (clear-) signing
   Copyright (C) 2009 g10 Code GmbH

   This file was adopted from LIBGPGME

   It is free software; you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   This code is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <gpgme.h>

#define PGM "gpgme-sign"
#include <gpgme.h>
#include <locale.h>
#include <errno.h>


#define fail_if_err(err)					\
  do								\
    {								\
      if (err)							\
        {							\
          fprintf (stderr, PGM": file %s line %d: <%s> %s\n",	\
                   __FILE__, __LINE__, gpgme_strsource (err),	\
           gpgme_strerror (err));			\
          exit (1);						\
        }							\
    }								\
  while (0)

static void
init_gpgme (gpgme_protocol_t proto)
{
  gpgme_error_t err;

  gpgme_check_version (NULL);
  setlocale (LC_ALL, "");
  gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
#ifndef HAVE_W32_SYSTEM
  gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
#endif

  err = gpgme_engine_check_version (proto);
  fail_if_err (err);
}

static void
print_data (gpgme_data_t dh)
{
#define BUF_SIZE 512
  char buf[BUF_SIZE + 1];
  int ret;

  ret = gpgme_data_seek (dh, 0, SEEK_SET);
  if (ret)
    fail_if_err (gpgme_err_code_from_errno (errno));
  while ((ret = gpgme_data_read (dh, buf, BUF_SIZE)) > 0)
    fwrite (buf, ret, 1, stdout);
  if (ret < 0)
    fail_if_err (gpgme_err_code_from_errno (errno));
}



static int
show_usage (int ex)
{
  fputs ("usage: " PGM " [options] FILE\n\n"
         "Options:\n"
         "  --key NAME       use key NAME for signing\n"
         , stderr);
  exit (ex);
}


int
main (int argc, char **argv)
{
  int last_argc = -1;
  gpgme_error_t err;
  gpgme_ctx_t ctx;
  const char *key_string = NULL;
  gpgme_protocol_t protocol = GPGME_PROTOCOL_OpenPGP;
  gpgme_sig_mode_t sigmode = GPGME_SIG_MODE_CLEAR;
  gpgme_data_t in, out;

  if (argc)
    { argc--; argv++; }

  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--"))
        {
          argc--; argv++;
          break;
        }
      else if (!strcmp (*argv, "--help"))
        show_usage (0);
      else if (!strcmp (*argv, "--key"))
        {
          argc--; argv++;
          if (!argc)
            show_usage (1);
          key_string = *argv;
          argc--; argv++;
        }
      else if (!strncmp (*argv, "--", 2))
        show_usage (1);

    }

  if (argc != 1)
    show_usage (1);

  init_gpgme (protocol);

  err = gpgme_new (&ctx);
  fail_if_err (err);
  gpgme_set_protocol (ctx, protocol);
  gpgme_set_armor (ctx, 1);

  if (key_string)
    {
      gpgme_key_t akey;

      err = gpgme_get_key (ctx, key_string, &akey, 1);
      if (err)
        {
          exit (1);
        }
      err = gpgme_signers_add (ctx, akey);
      fail_if_err (err);
      gpgme_key_unref (akey);
    }

  err = gpgme_data_new_from_file (&in, *argv, 1);
  if (err)
    {
      fprintf (stderr, PGM ": error reading `%s': %s\n",
               *argv, gpg_strerror (err));
      exit (1);
    }

  err = gpgme_data_new (&out);
  fail_if_err (err);

  err = gpgme_op_sign (ctx, in, out, sigmode);
  if (err)
    {
      fprintf (stderr, PGM ": signing failed: %s\n", gpg_strerror (err));
      exit (1);
    }

  print_data (out);
  gpgme_data_release (out);

  gpgme_data_release (in);

  gpgme_release (ctx);
  return 0;
}
