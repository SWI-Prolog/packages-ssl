/*  Part of SWI-Prolog

    Author:        Jan Wielemaker
    E-mail:        jan@swi-prolog.org
    WWW:           http://www.swi-prolog.org
    Copyright (c)  2024, SWI-Prolog Solutions b.v.
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

#ifndef SSL4PL_COMMON_H_INCLUDED
#define SSL4PL_COMMON_H_INCLUDED 1

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Unfortunately the OpenSSL/LibreSSL API is  not very stable.  This file
generalizes  a   few  things   to  give  them   a  shorter   and  more
understandable  name.   Ideally, all  these  should  be CMake  feature
tests.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

/* TBD: Should be checked by Cmake */
#if defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x3080000fL
#undef HAVE_X509_CHECK_HOST		/* seems broken. must investigate */
#endif

#if defined HAVE_EVP_PKEY_NEW && \
    defined HAVE_EVP_PKEY_FREE && \
    defined HAVE_EVP_PKEY_GET_BN_PARAM && \
    defined HAVE_EVP_PKEY_GET_OCTET_STRING_PARAM && \
    defined HAVE_EVP_PKEY_GET_SIZE && \
    defined HAVE_EVP_PKEY_DECRYPT && \
    defined HAVE_EVP_PKEY_ENCRYPT && \
    defined HAVE_EVP_PKEY_SIGN && \
    defined HAVE_EVP_PKEY_VERIFY && \
    defined HAVE_EVP_PKEY_Q_KEYGEN && \
    defined HAVE_OSSL_PARAM_CONSTRUCT_UTF8_STRING && \
    defined HAVE_BN_CHECK_PRIME && defined HAVE_OSSL_PARAM_BLD_NEW
#define USE_EVP_API 1
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
    (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x3050000fL)
#define SSL_API_0 1
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
#define SSL_API_0_OR_LIBRESSL 1
#endif

#endif /*SSL4PL_COMMON_H_INCLUDED*/
