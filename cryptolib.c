/*  Part of SWI-Prolog

    Author:        Markus Triska
    E-mail:        triska@metalevel.at
    WWW:           http://www.swi-prolog.org
    Copyright (c)  2004-2016, SWI-Prolog Foundation
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:

    1. Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in
       the documentation and/or other materials provided with the
       distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
    FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
    INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
    BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
    CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
    LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
    ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
*/

#include <config.h>
#include <string.h>

#include "cryptolib.h"

#if !defined(HAVE_OPENSSL_ZALLOC) && !defined(OPENSSL_zalloc)
static void *
OPENSSL_zalloc(size_t num)
{ void *ret = OPENSSL_malloc(num);
  if (ret != NULL)
    memset(ret, 0, num);
  return ret;
}
#endif

#ifndef HAVE_EVP_MD_CTX_FREE
static inline void
EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{ EVP_MD_CTX_cleanup(ctx);
  OPENSSL_free(ctx);
}

static inline EVP_MD_CTX *
EVP_MD_CTX_new(void)
{ return OPENSSL_zalloc(sizeof(EVP_MD_CTX));
}
#endif

static int
unify_bytes_hex(term_t t, size_t len, const unsigned char *data)
{ char tmp[512];
  char *out, *o;
  static const char *tohex = "0123456789ABCDEF";
  const unsigned char *end = data+len;
  int rc;

  if ( len*2 <= sizeof(tmp) )
    out = tmp;
  else if ( !(out = malloc(len*2)) )
    return PL_resource_error("memory");

  for(o=out ; data < end; data++)
  { *o++ = tohex[(*data >> 4) & 0xf];
    *o++ = tohex[(*data >> 0) & 0xf];
  }

  rc = PL_unify_chars(t, PL_STRING|REP_ISO_LATIN_1, len*2, out);
  if ( out != tmp )
    free(out);

  return rc;
}

static char *
ssl_strdup(const char *s)
{
    char *new = NULL;

    if (s != NULL && (new = malloc(strlen(s)+1)) != NULL) {
        strcpy(new, s);
    }
    return new;
}


/***********************************************************************
 * Warning, error and debug reporting
 ***********************************************************************/

/**
 * ssl_error_term(long ex) returns a Prolog term representing the SSL
 * error.  If there is already a pending exception, this is returned.
 *
 */
static int
ssl_error_term(long e)
{ term_t ex;
  char buffer[256];
  char* colon;
  char *component[5] = {NULL, "unknown", "unknown", "unknown", "unknown"};
  int n = 0;
  static functor_t FUNCTOR_error2 = 0;
  static functor_t FUNCTOR_ssl_error4 = 0;

  if ( (ex=PL_exception(0)) )
    return ex;					/* already pending exception */

  if ( !FUNCTOR_error2 )
  { FUNCTOR_error2     = PL_new_functor(PL_new_atom("error"),     2);
    FUNCTOR_ssl_error4 = PL_new_functor(PL_new_atom("ssl_error"), 4);
  }

  ERR_error_string_n(e, buffer, 256);

  /*
   * Disect the following error string:
   *
   * error:[error code]:[library name]:[function name]:[reason string]
   */
  if ( (ex=PL_new_term_ref()) )
  { for (colon = buffer, n = 0; n < 5 && colon != NULL; n++)
    { component[n] = colon;
      if ((colon = strchr(colon, ':')) == NULL) break;
      *colon++ = 0;
    }
    if ( PL_unify_term(ex,
		       PL_FUNCTOR, FUNCTOR_error2,
		       PL_FUNCTOR, FUNCTOR_ssl_error4,
		       PL_CHARS, component[1],
		       PL_CHARS, component[2],
		       PL_CHARS, component[3],
		       PL_CHARS, component[4],
		       PL_VARIABLE) )
    { return ex;
    }
  }

  return PL_exception(0);
}


static int
raise_ssl_error(long e)
{ term_t ex;

  if ( (ex = ssl_error_term(e)) )
    return PL_raise_exception(ex);

  return FALSE;
}


#ifdef NEED_SSL_ERR
static void
ssl_err(char *fmt, ...)
{
    va_list argpoint;

    va_start(argpoint, fmt);
	Svfprintf(Serror, fmt, argpoint);
    va_end(argpoint);
}
#endif

#ifdef NEED_SSL_SET_DEBUG
static int
ssl_set_debug(int level)
{ return nbio_debug(level);
}
#endif


static void
ssl_deb(int level, char *fmt, ...)
{
#if DEBUG
    if ( nbio_debug(-1) >= level )
    { va_list argpoint;

      fprintf(stderr, "Debug: ");
      va_start(argpoint, fmt);
      Svfprintf(Serror, fmt, argpoint);
      va_end(argpoint);
    }
#endif
}

static inline int
ssl_missing(const char *feature)
{ term_t t = PL_new_term_ref();

  return ( PL_put_atom_chars(t, feature) &&
	   PL_existence_error("ssl_feature", t) );

}


/*
 * BIO routines for SSL over streams
 */

#ifdef NEED_BIO

/*
 * Read function.
 */

static int
bio_read(BIO* bio, char* buf, int len)
{ IOSTREAM *stream = BIO_get_ex_data(bio, 0);

  return (int)Sread_pending(stream, buf, len, SIO_RP_BLOCK);
}

/*
 * Gets function. If only OpenSSL actually had usable documentation, I might know
 * what this was actually meant to do....
 */

static int
bio_gets(BIO* bio, char* buf, int len)
{ IOSTREAM *stream;
  int r = 0;
  stream = BIO_get_app_data(bio);

  for (r = 0; r < len; r++)
  { int c = Sgetc(stream);
    if (c == EOF)
      return r-1;
    buf[r] = (char)c;
    if (buf[r] == '\n')
      break;
  }

  return r;
}

/*
 * Write function
 */

static int
bio_write(BIO* bio, const char* buf, int len)
{ IOSTREAM* stream = BIO_get_ex_data(bio, 0);
  int r;

  r = (int)Sfwrite(buf, sizeof(char), len, stream);
  Sflush(stream);

  return r;
}

/*
 * Control function. Currently only supports flushing and detecting EOF.
 * There are several more mandatory, but as-yet unsupported functions...
 */

static long
bio_control(BIO* bio, int cmd, long num, void* ptr)
{ IOSTREAM* stream;
  stream  = BIO_get_ex_data(bio, 0);

  switch(cmd)
  { case BIO_CTRL_FLUSH:
      Sflush(stream);
      return 1;
    case BIO_CTRL_EOF:
      return Sfeof(stream);
  }

  return 0;
}

/*
 * Create function. Called when a new BIO is created
 * It is our responsibility to set init to 1 here
 */

static int
bio_create(BIO* bio)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
   bio->shutdown = 1;
   bio->init = 1;
   bio->num = -1;
   bio->ptr = NULL;
#else
   BIO_set_shutdown(bio, 1);
   BIO_set_init(bio, 1);
   /* bio->num = -1;  (what to do in OpenSSL >= 1.1.0?)
      bio->ptr = NULL; */
#endif
   return 1;
}

/*
 * Destroy function. Called when a BIO is freed
 */

static int
bio_destroy(BIO* bio)
{
   if (bio == NULL)
   {
      return 0;
   }
   return 1;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
/*
 * Specify the BIO read and write function structures
 */

static BIO_METHOD bio_read_functions = { BIO_TYPE_MEM,
                                         "read",
					 NULL,
					 &bio_read,
					 NULL,
					 &bio_gets,
					 &bio_control,
					 &bio_create,
					 &bio_destroy
				       };

static BIO_METHOD bio_write_functions = { BIO_TYPE_MEM,
					  "write",
					  &bio_write,
					  NULL,
					  NULL,
					  NULL,
					  &bio_control,
					  &bio_create,
					  &bio_destroy
					};

static BIO_METHOD *
bio_read_method(void)
{
  return &bio_read_functions;
}

static BIO_METHOD *
bio_write_method(void)
{
  return &bio_write_functions;
}
#else
/*
 * In OpenSSL >= 1.1.0, the BIO methods are constructed
 * using functions. We initialize them exactly once.
 */

static CRYPTO_ONCE once_read  = CRYPTO_ONCE_STATIC_INIT;
static CRYPTO_ONCE once_write = CRYPTO_ONCE_STATIC_INIT;

static BIO_METHOD *read_method = NULL;
static BIO_METHOD *write_method = NULL;

static void
read_method_init(void)
{
  BIO_METHOD *rm = BIO_meth_new(BIO_TYPE_MEM, "read");

  if ( rm == NULL ||
       (BIO_meth_set_read(rm, &bio_read) <= 0) ||
       (BIO_meth_set_gets(rm, &bio_gets) <= 0) ||
       (BIO_meth_set_ctrl(rm, &bio_control) <= 0) ||
       (BIO_meth_set_create(rm, &bio_create) <= 0) ||
       (BIO_meth_set_destroy(rm, &bio_destroy) <= 0) )
    return;

  read_method = rm;
}

static BIO_METHOD *
bio_read_method(void)
{
  if (read_method != NULL) return read_method;

  if ( !CRYPTO_THREAD_run_once(&once_read, read_method_init) )
    return NULL;

  return read_method;
}

static void
write_method_init(void)
{
  BIO_METHOD *wm = BIO_meth_new(BIO_TYPE_MEM, "write");

  if ( wm == NULL ||
       (BIO_meth_set_write(wm, &bio_write) <= 0) ||
       (BIO_meth_set_ctrl(wm, &bio_control) <= 0) ||
       (BIO_meth_set_create(wm, &bio_create) <= 0) ||
       (BIO_meth_set_destroy(wm, &bio_destroy) <= 0) )
    return;

  write_method = wm;
}

static BIO_METHOD *
bio_write_method(void)
{
  if (write_method != NULL) return write_method;

  if ( !CRYPTO_THREAD_run_once(&once_write, write_method_init) )
    return NULL;

  return write_method;
}
#endif

#endif /*NEED_BIO*/
