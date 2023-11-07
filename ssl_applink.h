/*  Part of SWI-Prolog

    Author:        Jan Wielemaker
    E-mail:        jan@swi-prolog.org
    WWW:           http://www.swi-prolog.org
    Copyright (c)  2023, SWI-Prolog Solutions b.v.
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

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
This file is a work  around  for   the  Windows  CRT  weirdness. The CRT
library can operate in two modes: shared over   the app or local to each
plugin. In the latter  case,  CRT  handles   such  as  FILE*  cannot  be
transferred between DLLs.

OpenSSL provides `<openssl/applink.c>`, which defines OPENSSL_Applink(),
that returns an array of function pointers  for the stdio functions used
by OpenSSL. This must be part of the main executable.

This module figures out wether that is   the  case and redefines fopen()
and fclose() in case it is such  that   we  get the CRT handles from the
right module.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

#include <config.h>

#ifdef HAVE_OPENSSL_APPLINK_C
#define APPMACROS_ONLY 1
#include <openssl/applink.c>

static int applink_done = FALSE;
static void **applink_table = NULL;

static void*
applink(int n)
{ if ( !applink_done )
  { HMODULE mod = GetModuleHandle(NULL);
    void**(*f)(void) = (void*)GetProcAddress(mod, "OPENSSL_Applink");
    if ( f )
      applink_table = f();
    applink_done = TRUE;
  }

  if ( applink_table )
    return applink_table[n];
  else
    return NULL;
}

static inline FILE*
app_fopen(const char *name, const char *mode)
{ FILE*(*f_fopen)(const char*, const char*) = applink(APPLINK_FOPEN);

  return f_fopen ? f_fopen(name, mode) : fopen(name, mode);
}

static inline int
app_fclose(FILE *fp)
{ int(*f_fclose)(FILE*) = applink(APPLINK_FCLOSE);

  return f_fclose ? f_fclose(fp) : fclose(fp);
}

#define fopen(name,mode)	app_fopen(name,mode)
#define fclose(fp)		app_fclose(fp)

#endif /*HAVE_OPENSSL_APPLINK_C*/
