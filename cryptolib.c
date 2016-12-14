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
#ifdef _REENTRANT
#include <pthread.h>
#endif

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
void
EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{ EVP_MD_CTX_cleanup(ctx);
  OPENSSL_free(ctx);
}

EVP_MD_CTX *
EVP_MD_CTX_new(void)
{ return OPENSSL_zalloc(sizeof(EVP_MD_CTX));
}
#endif


/***********************************************************************
 * Warning, error and debug reporting
 ***********************************************************************/

/**
 * ssl_error_term(long ex) returns a Prolog term representing the SSL
 * error.  If there is already a pending exception, this is returned.
 *
 */
int
ssl_error_term(long e)
{ term_t ex;
  char buffer[256];
  char* colon;
  char *component[5] = {NULL, "unknown", "unknown", "unknown", "unknown"};
  int n = 0;

  if ( (ex=PL_exception(0)) )
    return ex;					/* already pending exception */

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


int
raise_ssl_error(long e)
{ term_t ex;

  if ( (ex = ssl_error_term(e)) )
    return PL_raise_exception(ex);

  return FALSE;
}



void
ssl_msg(char *fmt, ...)
{
    va_list argpoint;

    va_start(argpoint, fmt);
	Svfprintf(Soutput, fmt, argpoint);
    va_end(argpoint);
}


void
ssl_err(char *fmt, ...)
{
    va_list argpoint;

    va_start(argpoint, fmt);
	Svfprintf(Serror, fmt, argpoint);
    va_end(argpoint);
}


int
ssl_set_debug(int level)
{ return nbio_debug(level);
}


void
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


                /*******************************
                *            THREADING         *
                *******************************/

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
OpenSSL is only thread-safe as of version 1.1.0.

For earlier versions, we need to install the hooks below. This code is
based on mttest.c distributed with the OpenSSL library.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

#ifdef _REENTRANT

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static pthread_mutex_t *lock_cs;
static long *lock_count;
static void (*old_locking_callback)(int, int, const char*, int) = NULL;
#ifdef HAVE_CRYPTO_THREADID_GET_CALLBACK
static void (*old_id_callback)(CRYPTO_THREADID*) = NULL;
#else
static unsigned long (*old_id_callback)(void) = NULL;
#endif

static void
pthreads_locking_callback(int mode, int type, const char *file, int line)
{ if (mode & CRYPTO_LOCK)
  { pthread_mutex_lock(&(lock_cs[type]));
    lock_count[type]++;
  } else
  { pthread_mutex_unlock(&(lock_cs[type]));
  }
}


/*  From OpenSSL manual:

    id_function(void) is a function that returns a thread ID. It is not
    needed on Windows nor on platforms where getpid() returns a different
    ID for each thread (most notably Linux).

    As for pthreads_win32 version 2, the thread identifier is no longer
    integral, we are going to test this claim from the manual

    JW: I don't think getpid() returns different thread ids on Linux any
    longer, nor on many other Unix systems. Maybe we should use
    PL_thread_self()?
*/

#ifndef __WINDOWS__
#ifdef HAVE_CRYPTO_THREADID_SET_CALLBACK
static void
pthreads_thread_id(CRYPTO_THREADID* id)
{ CRYPTO_THREADID_set_numeric(id, (unsigned long)pthread_self());
}
#else
static unsigned long
pthreads_thread_id(void)
{ unsigned long ret;

  ret=(unsigned long)pthread_self();
  return(ret);
}
#endif /* OpenSSL 1.0.0 */
#endif /* WINDOWS */
#endif /* OpenSSL 1.1.0 */

static void
crypto_thread_exit(void* ignored)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifdef HAVE_ERR_REMOVE_THREAD_STATE
  ERR_remove_thread_state(0);
#elif defined(HAVE_ERR_REMOVE_STATE)
  ERR_remove_state(0);
#else
#error "Do not know how to remove SSL error state"
#endif
#endif /* ERR_remove_(thread)_state is deprecated in OpenSSL >= 1.1.0 */
}

#ifndef HAVE_CRYPTO_THREADID_GET_CALLBACK
#define CRYPTO_THREADID_get_callback CRYPTO_get_id_callback
#define CRYPTO_THREADID_set_callback CRYPTO_set_id_callback
#endif

int
crypto_lib_init(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  if ( (old_id_callback=CRYPTO_THREADID_get_callback()) == 0 )
  { int i;

    lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));

    for (i=0; i<CRYPTO_num_locks(); i++)
    { lock_count[i]=0;
      pthread_mutex_init(&(lock_cs[i]), NULL);
    }

    old_locking_callback = CRYPTO_get_locking_callback();
#ifndef __WINDOWS__			/* JW: why not for Windows? */
    CRYPTO_THREADID_set_callback(pthreads_thread_id);
#endif
    CRYPTO_set_locking_callback(pthreads_locking_callback);

    PL_thread_at_exit(crypto_thread_exit, NULL, TRUE);
  }
#endif /*OPENSSL_VERSION_NUMBER < 0x10100000L*/

  return TRUE;
}

#else /*_REENTRANT*/

int
crypto_lib_init(void)
{ return FALSE;
}

#endif /*_REENTRANT*/


int
crypto_lib_exit(void)
/*
 * One-time library exit calls
 */
{
/*
 * If the module is being unloaded, we should remove callbacks pointing to
 * our address space
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifdef _REENTRANT
#ifndef __WINDOWS__
    CRYPTO_THREADID_set_callback(old_id_callback);
#endif
    CRYPTO_set_locking_callback(old_locking_callback);
#endif
#endif
    return 0;
}
