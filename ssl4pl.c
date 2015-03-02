/*  Part of SWI-Prolog

    Author:        Jan van der Steen, Jan Wielemaker and Matt Lilley
    E-mail:        J.Wielemaker@vu.nl
    WWW:           http://www.swi-prolog.org
    Copyright (C): 1985-2015, SWI-Prolog Foundation
			      VU University Amsterdam

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/


#include <SWI-Stream.h>
#include <SWI-Prolog.h>
#include <assert.h>
#include <string.h>
#include "ssllib.h"

#ifdef _REENTRANT
#include <pthread.h>
#endif

static atom_t ATOM_server;
static atom_t ATOM_client;
static atom_t ATOM_password;
static atom_t ATOM_cert;
static atom_t ATOM_peer_cert;
static atom_t ATOM_cacert_file;
static atom_t ATOM_certificate_file;
static atom_t ATOM_key_file;
static atom_t ATOM_pem_password_hook;
static atom_t ATOM_cert_verify_hook;
static atom_t ATOM_close_parent;
static atom_t ATOM_disable_ssl_methods;
static atom_t ATOM_root_certificates;

static atom_t ATOM_sslv2;
static atom_t ATOM_sslv23;
static atom_t ATOM_sslv3;
static atom_t ATOM_tlsv1;
static atom_t ATOM_tlsv1_1;
static atom_t ATOM_tlsv1_2;
static atom_t ATOM_minus;			/* "-" */

static functor_t FUNCTOR_unsupported_hash_algorithm1;
static functor_t FUNCTOR_system1;
       functor_t FUNCTOR_error2;	/* also used in ssllib.c */
       functor_t FUNCTOR_ssl_error4;	/* also used in ssllib.c */
static functor_t FUNCTOR_permission_error3;
static functor_t FUNCTOR_ip4;
static functor_t FUNCTOR_version1;
static functor_t FUNCTOR_notbefore1;
static functor_t FUNCTOR_notafter1;
static functor_t FUNCTOR_subject1;
static functor_t FUNCTOR_issuername1;
static functor_t FUNCTOR_serial1;
static functor_t FUNCTOR_public_key1;
static functor_t FUNCTOR_private_key1;
static functor_t FUNCTOR_rsa8;
static functor_t FUNCTOR_key1;
static functor_t FUNCTOR_hash1;
static functor_t FUNCTOR_next_update1;
static functor_t FUNCTOR_signature1;
static functor_t FUNCTOR_equals2;
static functor_t FUNCTOR_crl1;
static functor_t FUNCTOR_revocations1;
static functor_t FUNCTOR_revoked2;
static functor_t FUNCTOR_session_key1;
static functor_t FUNCTOR_master_key1;
static functor_t FUNCTOR_session_id1;
static functor_t FUNCTOR_client_random1;
static functor_t FUNCTOR_server_random1;
static functor_t FUNCTOR_system1;

static int i2d_X509_CRL_INFO_wrapper(void* i, unsigned char** d)
{
   return i2d_X509_CRL_INFO(i, d);
}

static int i2d_X509_CINF_wrapper(void* i, unsigned char** d)
{
   return i2d_X509_CINF(i, d);
}

static int
get_char_arg(int a, term_t t, char **s)
{ term_t t2 = PL_new_term_ref();

  _PL_get_arg(a, t, t2);
  if ( !PL_get_chars(t2, s, CVT_ATOM|CVT_STRING|CVT_EXCEPTION) )
    return FALSE;

  return TRUE;
}


static int
get_bool_arg(int a, term_t t, int *i)
{ term_t t2 = PL_new_term_ref();

  _PL_get_arg(a, t, t2);
  if ( !PL_get_bool_ex(t2, i) )
    return FALSE;

  return TRUE;
}


static int
get_file_arg(int a, term_t t, char **f)
{ term_t t2 = PL_new_term_ref();

  _PL_get_arg(a, t, t2);
  if ( !PL_get_file_name(t2, f, PL_FILE_EXIST) )
    return FALSE;

  return TRUE;
}


static int
get_predicate_arg(int a, module_t m, term_t t, int arity, predicate_t *pred)
{ term_t t2 = PL_new_term_ref();
  atom_t name;

  _PL_get_arg(a, t, t2);
  PL_strip_module(t2, &m, t2);
  if ( !PL_get_atom_ex(t2, &name) )
    return FALSE;

  *pred = PL_pred(PL_new_functor(name, arity), m);

  return TRUE;
}


static int
get_bn_arg(int a, term_t t, BIGNUM **bn)
{ term_t arg;
  char *hex;

  if ( (arg=PL_new_term_ref()) &&
       PL_get_arg(a, t, arg) &&
       PL_get_chars(arg, &hex,
		    CVT_ATOM|CVT_STRING|REP_ISO_LATIN_1|CVT_EXCEPTION) )
  { if ( strcmp(hex, "-") == 0 )
      *bn = NULL;
    else
      BN_hex2bn(bn, hex);

    return TRUE;
  }

  return FALSE;
}


static int
unify_bignum_arg(int a, term_t t, const BIGNUM *bn)
{ term_t arg;

  if ( (arg = PL_new_term_ref()) &&
       PL_get_arg(a, t, arg) )
  { int rc;

    if ( bn )
    { char *hex = BN_bn2hex(bn);

      rc = PL_unify_chars(arg, PL_STRING|REP_ISO_LATIN_1, (size_t)-1, hex);
      OPENSSL_free(hex);
    } else
      rc = PL_unify_atom(arg, ATOM_minus);

    PL_reset_term_refs(arg);
    return rc;
  }

  return FALSE;
}


static int
recover_rsa(term_t t, RSA** rsap)
{ RSA *rsa = RSA_new();

  if ( get_bn_arg(1, t, &rsa->n) &&
       get_bn_arg(2, t, &rsa->e) &&
       get_bn_arg(3, t, &rsa->d) &&
       get_bn_arg(4, t, &rsa->p) &&
       get_bn_arg(5, t, &rsa->q) &&
       get_bn_arg(6, t, &rsa->dmp1) &&
       get_bn_arg(7, t, &rsa->dmq1) &&
       get_bn_arg(8, t, &rsa->iqmp)
     )
  { *rsap = rsa;
    return TRUE;
  }

  RSA_free(rsa);
  return FALSE;
}


static int
recover_private_key(term_t t, RSA** rsap)
{ if ( PL_is_functor(t, FUNCTOR_private_key1) )
  { term_t arg;

    if ( (arg = PL_new_term_ref()) &&
	 PL_get_arg(1, t, arg) )
      return recover_rsa(arg, rsap);

    return FALSE;
  }

  return PL_type_error("private_key", t);
}


static int
recover_public_key(term_t t, RSA** rsap)
{ if ( PL_is_functor(t, FUNCTOR_public_key1) )
  { term_t arg;

    if ( (arg = PL_new_term_ref()) &&
	 PL_get_arg(1, t, arg) )
      return recover_rsa(arg, rsap);

    return FALSE;
  }

  return PL_type_error("public_key", t);
}


static int
unify_rsa(term_t item, RSA* rsa)
{ return ( PL_unify_functor(item, FUNCTOR_rsa8) &&
	   unify_bignum_arg(1, item, rsa->n) &&
	   unify_bignum_arg(2, item, rsa->e) &&
	   unify_bignum_arg(3, item, rsa->d) &&
	   unify_bignum_arg(4, item, rsa->p) &&
	   unify_bignum_arg(5, item, rsa->q) &&
	   unify_bignum_arg(6, item, rsa->dmp1) &&
	   unify_bignum_arg(7, item, rsa->dmq1) &&
	   unify_bignum_arg(8, item, rsa->iqmp)
	 );
}


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


/* Note that while this might seem incredibly hacky, it is
   essentially the same algorithm used by X509_cmp_time to
   parse the date. Some
   Fractional seconds are ignored. This is also largely untested - there
   may be a lot of edge cases that dont work!
*/
static int
unify_asn1_time(term_t term, ASN1_TIME *time)
{ time_t result = 0;
  char buffer[24];
  char* pbuffer = buffer;
  size_t length = time->length;
  char * source = (char *)time->data;
  struct tm time_tm;
  time_t lSecondsFromUTC;

  if (time->type == V_ASN1_UTCTIME)
  {  if ((length < 11) || (length > 17))
     {  ssl_deb(2, "Unable to parse time - expected either 11 or 17 chars, not %d", length);
        return FALSE;
     }
     /* Otherwise just get the first 10 chars - ignore seconds */
     memcpy(pbuffer, source, 10);
     pbuffer += 10;
     source += 10;
     length -= 10;
  } else
  { if (length < 13)
     {  ssl_deb(2, "Unable to parse time - expected at least 13 chars, not %d", length);
        return FALSE;
     }
     /* Otherwise just get the first 12 chars - ignore seconds */
     memcpy(pbuffer, source, 12);
     pbuffer += 12;
     source += 12;
     length -= 12;
  }
  /* Next find end of string */
  if ((*source == 'Z') || (*source == '-') || (*source == '+'))
  { *(pbuffer++) = '0';
    *(pbuffer++) = '0';
  } else
  { *(pbuffer++) = *(source++);
    *(pbuffer++) = *(source++);
    if (*source == '.')
    { source++;
      while ((*source >= '0') && (*source <= '9'))
         source++;
    }
  }
  *(pbuffer++) = 'Z';
  *(pbuffer++) = '\0';

  /* If not UTC, calculate offset */
  if (*source == 'Z')
     lSecondsFromUTC = 0;
  else
  { if ( length < 6 || (*source != '+' && source[5] != '-') )
     {  ssl_deb(2, "Unable to parse time. Missing UTC offset");
        return FALSE;
     }
     lSecondsFromUTC = ((source[1]-'0') * 10 + (source[2]-'0')) * 60;
     lSecondsFromUTC += (source[3]-'0') * 10 + (source[4]-'0');
     if (*source == '-')
        lSecondsFromUTC = -lSecondsFromUTC;
  }
  /* Parse date */
  time_tm.tm_sec  = ((buffer[10] - '0') * 10) + (buffer[11] - '0');
  time_tm.tm_min  = ((buffer[8] - '0') * 10) + (buffer[9] - '0');
  time_tm.tm_hour = ((buffer[6] - '0') * 10) + (buffer[7] - '0');
  time_tm.tm_mday = ((buffer[4] - '0') * 10) + (buffer[5] - '0');
  time_tm.tm_mon  = (((buffer[2] - '0') * 10) + (buffer[3] - '0')) - 1;
  time_tm.tm_year = ((buffer[0] - '0') * 10) + (buffer[1] - '0');
  if (time_tm.tm_year < 50)
     time_tm.tm_year += 100; /* according to RFC 2459 */
  time_tm.tm_wday = 0;
  time_tm.tm_yday = 0;
  time_tm.tm_isdst = 0;  /* No DST adjustment requested, though mktime might do it anyway */

#ifdef HAVE_TIMEGM
  result = timegm(&time_tm);
  if ((time_t)-1 != result)
  { result += lSecondsFromUTC;
  } else
  { ssl_deb(2, "timegm() failed");
    return FALSE;
  }
#else
  result = mktime(&time_tm);
  /* mktime assumes that the time_tm contains information for localtime. Convert back to UTC: */
  if ((time_t)-1 != result)
  { result += lSecondsFromUTC; /* Add in the UTC offset of the original value */
    result -= timezone; /* Adjust for localtime */
  } else
  { ssl_deb(2, "mktime() failed");
    return FALSE;
  }
#endif

  return PL_unify_int64(term, result);
}

static int
unify_hash(term_t hash, ASN1_OBJECT* algorithm, int (*i2d)(void*, unsigned char**), void * data)
{ const EVP_MD *type;
  EVP_MD_CTX ctx;
  int digestible_length;
  unsigned char* digest_buffer;
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int digest_length;
  unsigned char* p;
  int nid = 0;
  /* Generate hash */
  nid = OBJ_obj2nid(algorithm);
  /* Annoyingly, EVP_get_digestbynid doesnt work for some of these algorithms. Instead check for
     them explicitly and set the digest manually
  */
  if (nid == NID_ecdsa_with_SHA1)
  { type = EVP_sha1();
  } else if (nid == NID_ecdsa_with_SHA256)
  { type = EVP_sha256();
  } else if (nid == NID_ecdsa_with_SHA384)
  { type = EVP_sha384();
#ifdef HAVE_OPENSSL_MD2_H
  } else if (nid == NID_md2WithRSAEncryption)
  { type = EVP_md2();
#endif
  } else
  { type = EVP_get_digestbynid(nid);
    if (type == NULL)
      return PL_unify_term(hash,
                           PL_FUNCTOR, FUNCTOR_unsupported_hash_algorithm1,
                           PL_INTEGER, nid);
  }
  EVP_MD_CTX_init(&ctx);

  digestible_length=i2d(data,NULL);
  digest_buffer = PL_malloc(digestible_length);
  if (digest_buffer == NULL)
    return PL_resource_error("memory");

  /* i2d_X509_CINF will change the value of p. We need to pass in a copy */
  p = digest_buffer;
  i2d(data,&p);
  if (!EVP_DigestInit(&ctx, type))
  { EVP_MD_CTX_cleanup(&ctx);
    PL_free(digest_buffer);
    return raise_ssl_error(ERR_get_error());
  }
  if (!EVP_DigestUpdate(&ctx, digest_buffer, digestible_length))
  { EVP_MD_CTX_cleanup(&ctx);
    PL_free(digest_buffer);
    return raise_ssl_error(ERR_get_error());
  }
  if (!EVP_DigestFinal(&ctx, digest, &digest_length))
  { EVP_MD_CTX_cleanup(&ctx);
    PL_free(digest_buffer);
    return raise_ssl_error(ERR_get_error());
  }
  EVP_MD_CTX_cleanup(&ctx);
  PL_free(digest_buffer);
  return unify_bytes_hex(hash, digest_length, digest);
}

static int
unify_name(term_t term, X509_NAME* name)
{ int ni;
  term_t list = PL_copy_term_ref(term);
  term_t item = PL_new_term_ref();

  if (name == NULL)
     return PL_unify_term(term,
                          PL_CHARS, "<null>");
  for (ni = 0; ni < X509_NAME_entry_count(name); ni++)
  { X509_NAME_ENTRY* e = X509_NAME_get_entry(name, ni);
    ASN1_STRING* entry_data = X509_NAME_ENTRY_get_data(e);
    unsigned char *utf8_data;
    int rc;

    if ( ASN1_STRING_to_UTF8(&utf8_data, entry_data) < 0 )
      return PL_resource_error("memory");

    rc = ( PL_unify_list(list, item, list) &&
	   PL_unify_term(item,
			 PL_FUNCTOR, FUNCTOR_equals2,
			 PL_CHARS, OBJ_nid2sn(OBJ_obj2nid(e->object)),
			 PL_UTF8_CHARS, utf8_data)
	 );
    OPENSSL_free(utf8_data);
    if ( !rc )
      return FALSE;
  }
  return PL_unify_nil(list);
}

static int
unify_crl(term_t term, X509_CRL* crl)
{ X509_CRL_INFO* info = crl->crl;
  int i;
  term_t item = PL_new_term_ref();
  term_t hash = PL_new_term_ref();
  term_t issuer = PL_new_term_ref();
  term_t revocations = PL_new_term_ref();
  term_t list = PL_copy_term_ref(revocations);
  term_t next_update = PL_new_term_ref();
  term_t signature = PL_new_term_ref();

  int result = 1;
  long n;
  unsigned char* p;
  term_t revocation_date;
  BIO* mem;

  mem = BIO_new(BIO_s_mem());
  if (mem == NULL)
    return PL_resource_error("memory");

  i2a_ASN1_INTEGER(mem, crl->signature);
  if (!(unify_name(issuer, X509_CRL_get_issuer(crl)) &&
        unify_hash(hash, crl->sig_alg->algorithm, i2d_X509_CRL_INFO_wrapper, crl->crl) &&
        unify_asn1_time(next_update, X509_CRL_get_nextUpdate(crl)) &&
	unify_bytes_hex(signature, crl->signature->length, crl->signature->data) &&
        PL_unify_term(term,
                      PL_LIST, 5,
                      PL_FUNCTOR, FUNCTOR_issuername1,
                      PL_TERM, issuer,
                      PL_FUNCTOR, FUNCTOR_signature1,
                      PL_TERM, signature,
                      PL_FUNCTOR, FUNCTOR_hash1,
                      PL_TERM, hash,
                      PL_FUNCTOR, FUNCTOR_next_update1,
                      PL_TERM, next_update,
                      PL_FUNCTOR, FUNCTOR_revocations1,
                      PL_TERM, revocations)))
  {
     return FALSE;
  }
  for (i = 0; i < sk_X509_REVOKED_num(info->revoked); i++)
  {
     X509_REVOKED* revoked = sk_X509_REVOKED_value(info->revoked, i);
     (void)BIO_reset(mem);
     i2a_ASN1_INTEGER(mem, revoked->serialNumber);
     result &= (((n = BIO_get_mem_data(mem, &p)) > 0) &&
                PL_unify_list(list, item, list) &&
                (revocation_date = PL_new_term_ref()) &&
                unify_asn1_time(revocation_date, revoked->revocationDate) &&
                PL_unify_term(item,
                              PL_FUNCTOR, FUNCTOR_revoked2,
                              PL_NCHARS, (size_t)n, p,
                              PL_TERM, revocation_date));
     if (BIO_reset(mem) != 1)
     {
        BIO_free(mem);
        // The only reason I can imagine this would fail is out of memory
        return PL_resource_error("memory");
     }
  }
  BIO_free(mem);
  return result && PL_unify_nil(list);
}


static int
unify_key(EVP_PKEY* key, functor_t type, term_t item)
{ if ( !PL_unify_functor(item, type) ||
       !PL_get_arg(1, item, item) )
    return FALSE;

 /* EVP_PKEY_get1_* returns a copy of the existing key */
  switch (EVP_PKEY_type(key->type))
  { int rc;
#ifndef OPENSSL_NO_RSA
    case EVP_PKEY_RSA:
    { RSA* rsa = EVP_PKEY_get1_RSA(key);
      rc = unify_rsa(item, rsa);
      RSA_free(rsa);
      return rc;
    }
#endif
#ifndef OPENSSL_NO_EC
    case EVP_PKEY_EC:
    { EC_KEY* ec = EVP_PKEY_get1_EC_KEY(key);
      rc = PL_unify_atom_chars(item, "ec_key");
      EC_KEY_free(ec);
      return rc;
    }
#endif
#ifndef OPENSSL_NO_DH
    case EVP_PKEY_DH:
    { DH* dh = EVP_PKEY_get1_DH(key);
      rc = PL_unify_atom_chars(item, "dh_key");
      DH_free(dh);
      return rc;
    }
#endif
#ifndef OPENSSL_NO_DSA
    case EVP_PKEY_DSA:
    { DSA* dsa = EVP_PKEY_get1_DSA(key);
      rc = PL_unify_atom_chars(item, "dsa_key");
      DSA_free(dsa);
      return rc;
    }
#endif
  default:
    /* Unknown key type */
    return PL_representation_error("ssl_key");
  }
  return TRUE;
}

static int
unify_public_key(EVP_PKEY* key, term_t item)
{ return unify_key(key, FUNCTOR_public_key1, item);
}

static int
unify_private_key(EVP_PKEY* key, term_t item)
{ return unify_key(key, FUNCTOR_private_key1, item);
}


static int
unify_certificate(term_t cert, X509* data)
{ term_t list = PL_copy_term_ref(cert);
  term_t item = PL_new_term_ref();
  BIO * mem = NULL;
  long n;
  EVP_PKEY *key;
  term_t issuername;
  term_t subject;
  term_t hash;
  term_t not_before;
  term_t not_after;
  term_t signature;
  unsigned int crl_ext_id;
  unsigned char *p;
  X509_EXTENSION * crl_ext = NULL;


  if (!(PL_unify_list(list, item, list) &&
        PL_unify_term(item,
                      PL_FUNCTOR, FUNCTOR_version1,
                      PL_LONG, X509_get_version(data))
         ))
     return FALSE;
  if (!(PL_unify_list(list, item, list) &&
        (not_before = PL_new_term_ref()) &&
        unify_asn1_time(not_before, X509_get_notBefore(data)) &&
        PL_unify_term(item,
                      PL_FUNCTOR, FUNCTOR_notbefore1,
                      PL_TERM, not_before)))
     return FALSE;

  if (!(PL_unify_list(list, item, list) &&
        (not_after = PL_new_term_ref()) &&
        unify_asn1_time(not_after, X509_get_notAfter(data)) &&
        PL_unify_term(item,
                      PL_FUNCTOR, FUNCTOR_notafter1,
                      PL_TERM, not_after)))
     return FALSE;


  if ((mem = BIO_new(BIO_s_mem())) != NULL)
  { i2a_ASN1_INTEGER(mem, X509_get_serialNumber(data));
    if ((n = BIO_get_mem_data(mem, &p)) > 0)
    {  if (!(PL_unify_list(list, item, list) &&
             PL_unify_term(item,
                           PL_FUNCTOR, FUNCTOR_serial1,
                           PL_NCHARS, (size_t)n, p)
              ))
        { BIO_vfree(mem);
          return FALSE;
        }
    } else
      Sdprintf("Failed to print serial - continuing without serial\n");
  } else
    Sdprintf("Failed to allocate BIO for printing - continuing without serial\n");
  BIO_vfree(mem);

  if (!(PL_unify_list(list, item, list) &&
        (subject = PL_new_term_ref()) &&
        unify_name(subject, X509_get_subject_name(data)) &&
        PL_unify_term(item,
                      PL_FUNCTOR, FUNCTOR_subject1,
                      PL_TERM, subject))
     )
     return FALSE;
  if (!((hash = PL_new_term_ref()) &&
        unify_hash(hash, data->sig_alg->algorithm, i2d_X509_CINF_wrapper, data->cert_info) &&
        PL_unify_list(list, item, list) &&
        PL_unify_term(item,
                      PL_FUNCTOR, FUNCTOR_hash1,
                      PL_TERM, hash)))
     return FALSE;
  if (!((signature = PL_new_term_ref()) &&
	unify_bytes_hex(signature,
			data->signature->length, data->signature->data) &&
	PL_unify_list(list, item, list) &&
        PL_unify_term(item,
                      PL_FUNCTOR, FUNCTOR_signature1,
                      PL_TERM, signature)
         ))
     return FALSE;

  if (!(PL_unify_list(list, item, list) &&
        (issuername = PL_new_term_ref()) &&
        unify_name(issuername, X509_get_issuer_name(data)) &&
        PL_unify_term(item,
                      PL_FUNCTOR, FUNCTOR_issuername1,
                      PL_TERM, issuername))
     )
     return FALSE;

  if (!PL_unify_list(list, item, list))
    return FALSE;
  /* X509_extract_key returns a copy of the existing key */
  key = X509_extract_key(data);
  if ( !PL_unify_functor(item, FUNCTOR_key1) ||
       !PL_get_arg(1, item, item) ||
       !unify_public_key(key, item) )
    return FALSE;
  EVP_PKEY_free(key);


  /* If the cert has a CRL distribution point, return that. If it does not,
     it is not an error
  */
  crl_ext_id = X509_get_ext_by_NID(data, NID_crl_distribution_points, -1);
  crl_ext = X509_get_ext(data, crl_ext_id);
  if (crl_ext != NULL)
  { STACK_OF(DIST_POINT) * distpoints;
    int i, j;
    term_t crl;
    term_t crl_list;
    term_t crl_item;

    if (!PL_unify_list(list, item, list))
       return FALSE;

    distpoints = X509_get_ext_d2i(data, NID_crl_distribution_points, NULL, NULL);
    /* Loop through the CRL points, putting them into a list */
    crl = PL_new_term_ref();
    crl_list = PL_copy_term_ref(crl);
    crl_item = PL_new_term_ref();

    for (i = 0; i < sk_DIST_POINT_num(distpoints); i++)
    { DIST_POINT *point;
      GENERAL_NAME *name;
      point = sk_DIST_POINT_value(distpoints, i);
      if (point->distpoint != NULL)
      { /* Each point may have several names? May as well put them all in */
        for (j = 0; j < sk_GENERAL_NAME_num(point->distpoint->name.fullname); j++)
        { name = sk_GENERAL_NAME_value(point->distpoint->name.fullname, j);
          if (name != NULL && name->type == GEN_URI)
          { if (!(PL_unify_list(crl_list, crl_item, crl_list) &&
                  PL_unify_atom_chars(crl_item, (const char *)name->d.ia5->data)))
            {
              CRL_DIST_POINTS_free(distpoints);
              return FALSE;
            }
          }
        }
      }
    }
    CRL_DIST_POINTS_free(distpoints);
    if (!PL_unify_nil(crl_list))
       return FALSE;
    if (!PL_unify_term(item,
                       PL_FUNCTOR, FUNCTOR_crl1,
                       PL_TERM, crl))
       return FALSE;
  }
  return PL_unify_nil(list);
}

static int
unify_certificates(term_t certs, term_t tail, STACK_OF(X509)* stack)
{ term_t item = PL_new_term_ref();
  term_t list = PL_copy_term_ref(certs);
  X509* cert = sk_X509_pop(stack);
  int retval = 1;

  while (cert != NULL && retval == 1)
  { retval &= PL_unify_list(list, item, list);
    retval &= unify_certificate(item, cert);
    X509_free(cert);
    cert = sk_X509_pop(stack);
    if (cert == NULL)
      return PL_unify(tail, item) && PL_unify_nil(list);
  }
  return retval && PL_unify_nil(list);
}

static foreign_t
pl_load_public_key(term_t source, term_t key_t)
{ EVP_PKEY* key;
  BIO* bio;
  IOSTREAM* stream;
  int c;

  if ( !PL_get_stream_handle(source, &stream) )
    return FALSE;
  bio = BIO_new(&bio_read_functions);
  BIO_set_ex_data(bio, 0, stream);

  /* Determine format */
  c = Speekcode(stream);
  if (c == 0x30)  /* ASN.1 sequence, so assume DER */
     key = d2i_PUBKEY_bio(bio, NULL);
  else
     key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  BIO_free(bio);
  PL_release_stream(stream);
  if (key == NULL)
     return PL_permission_error("read", "key", source);
  if (!unify_public_key(key, key_t))
  { EVP_PKEY_free(key);
    PL_fail;
  }
  EVP_PKEY_free(key);
  PL_succeed;
}


static int
private_password_callback(char *buf, int bufsiz, int verify, void* pw)
{ char *password = (char*)pw;
  size_t res = strlen(password);

  if ( res > (size_t)bufsiz )
    res = bufsiz;
  memcpy(buf, password, res);

  return res;
}

static foreign_t
pl_load_private_key(term_t source, term_t password, term_t key_t)
{ EVP_PKEY* key;
  BIO* bio;
  IOSTREAM* stream;
  char* password_chars;
  int c, rc;

  if ( !PL_get_chars(password, &password_chars,
		     CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION) )
    return FALSE;
  if ( !PL_get_stream_handle(source, &stream) )
    return FALSE;
  bio = BIO_new(&bio_read_functions);
  BIO_set_ex_data(bio, 0, stream);

  /* Determine format */
  c = Speekcode(stream);
  if (c == 0x30)  /* ASN.1 sequence, so assume DER */
    key = d2i_PrivateKey_bio(bio, NULL); /* TBD: Password! */
  else
    key = PEM_read_bio_PrivateKey(bio, NULL,
				  &private_password_callback,
				  (void*)password_chars);
  BIO_free(bio);
  PL_release_stream(stream);

  if ( key == NULL )
    return PL_permission_error("read", "key", source);

  rc = (unify_private_key(key, key_t) != 0);
  EVP_PKEY_free(key);

  return rc;
}

static foreign_t
pl_load_crl(term_t source, term_t list)
{ X509_CRL* crl;
  BIO* bio;
  IOSTREAM* stream;
  int result;
  int c;

  if ( !PL_get_stream_handle(source, &stream) )
    return FALSE;

  bio = BIO_new(&bio_read_functions);
  BIO_set_ex_data(bio, 0, stream);
  /* Determine the format of the CRL */
  c = Speekcode(stream);
  if (c == 0x30)  /* ASN.1 sequence, so assume DER */
     crl = d2i_X509_CRL_bio(bio, NULL);
  else
     crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
  BIO_free(bio);
  PL_release_stream(stream);
  if (crl == NULL)
  { ssl_deb(2, "Failed to load CRL");
    PL_fail;
  }
  result = unify_crl(list, crl);
  X509_CRL_free(crl);
  return result;
}

static foreign_t
pl_load_certificate(term_t source, term_t cert)
{ X509* x509;
  BIO* bio;
  IOSTREAM* stream;
  int c = 0;

  if ( !PL_get_stream_handle(source, &stream) )
    return FALSE;
  bio = BIO_new(&bio_read_functions);
  BIO_set_ex_data(bio, 0, stream);
  /* Determine format */
  c = Speekcode(stream);
  if (c == 0x30)  /* ASN.1 sequence, so assume DER */
     x509 = d2i_X509_bio(bio, NULL);
  else
     x509 = PEM_read_bio_X509(bio, NULL, 0, NULL);
  BIO_free(bio);
  PL_release_stream(stream);
  if (x509 == NULL)
    return raise_ssl_error(ERR_get_error());
  if (unify_certificate(cert, x509))
  { X509_free(x509);
    PL_succeed;
  } else
  { X509_free(x509);
    PL_fail;
  }
}


static void
acquire_ssl(atom_t atom)
{ ssl_deb(4, "Acquire on atom %d\n", atom);
}


static int
release_ssl(atom_t atom)
{ PL_SSL* conf;
  size_t size;

  conf = PL_blob_data(atom, &size, NULL);
  ssl_deb(4, "Releasing PL_SSL %p\n", conf);
  ssl_exit(conf);	/* conf is freed by an internal call from OpenSSL
	                   via ssl_config_free() */
  return TRUE;
}

static int
compare_ssl(atom_t a, atom_t b)
{ PL_SSL* *ssla = PL_blob_data(a, NULL, NULL);
  PL_SSL* *sslb = PL_blob_data(b, NULL, NULL);

  return ( ssla > sslb ?  1 :
	   ssla < sslb ? -1 : 0
	 );
}

static int
write_ssl(IOSTREAM *s, atom_t symbol, int flags)
{ PL_SSL *ssl = PL_blob_data(symbol, NULL, NULL);

  Sfprintf(s, "<ssl_context>(%p)", ssl);

  return TRUE;
}

static PL_blob_t ssl_context_type =
{ PL_BLOB_MAGIC,
  PL_BLOB_NOCOPY,
  "ssl_context",
  release_ssl,
  compare_ssl,
  write_ssl,
  acquire_ssl
};


static int
put_conf(term_t config, PL_SSL *conf)
{ return PL_unify_atom(config, conf->atom);
}


static int
register_conf(term_t config, PL_SSL *conf)
{ term_t blob = PL_new_term_ref();
  int rc;

  PL_put_blob(blob, conf, sizeof(void*), &ssl_context_type);
  rc = PL_get_atom(blob, &conf->atom);
  assert(rc);
  ssl_deb(4, "Atom created: %d\n", conf->atom);
  return put_conf(config, conf);
}


static int
get_conf(term_t config, PL_SSL **conf)
{ PL_blob_t *type;
  void *data;

  if ( PL_get_blob(config, &data, NULL, &type) && type == &ssl_context_type )
  { PL_SSL *ssl = data;

    assert(ssl->magic == SSL_CONFIG_MAGIC);
    *conf = ssl;

    return TRUE;
  }

  return PL_type_error("ssl_context", config);
}


		 /*******************************
		 *	      CALLBACK		*
		 *******************************/


static char *
pl_pem_passwd_hook(PL_SSL *config, char *buf, int size)
{ fid_t fid = PL_open_foreign_frame();
  term_t av = PL_new_term_refs(2);
  predicate_t pred = (predicate_t) config->pl_ssl_cb_pem_passwd_data;
  char *passwd = NULL;
  size_t len;

  /*
   * hook(+SSL, -Passwd)
   */

  put_conf(av+0, config);
  if ( PL_call_predicate(NULL, PL_Q_PASS_EXCEPTION, pred, av) )
  { if ( PL_get_nchars(av+1, &len, &passwd, CVT_ALL) )
    { if ( len >= (unsigned int)size )
	PL_warning("pem_passwd too long");
      else
	memcpy(buf, passwd, len);
    } else
      PL_warning("pem_passwd_hook returned wrong type");
  }

  PL_close_foreign_frame(fid);

  return passwd;
}


static BOOL
pl_cert_verify_hook(PL_SSL *config,
                    X509 * cert,
		    X509_STORE_CTX * ctx,
		    const char *error)
{ fid_t fid = PL_open_foreign_frame();
  term_t av = PL_new_term_refs(5);
  predicate_t pred = (predicate_t) config->pl_ssl_cb_cert_verify_data;
  int val;
  STACK_OF(X509)* stack;

  assert(pred);

  stack = X509_STORE_CTX_get1_chain(ctx);


  /*
   * hook(+SSL, +Certificate, +Error)
   */

  put_conf(av+0, config);
  /*Sdprintf("\n---Certificate:'%s'---\n", certificate);*/
  val = ( unify_certificate(av+1, cert) &&
          unify_certificates(av+2, av+3, stack) &&
	  PL_unify_atom_chars(av+4, error) &&
	  PL_call_predicate(NULL, PL_Q_PASS_EXCEPTION, pred, av) );

  /* free any items still on stack, since X509_STORE_CTX_get1_chain returns a copy */
  sk_X509_pop_free(stack, X509_free);
  PL_close_foreign_frame(fid);

  return val;
}


static foreign_t
pl_ssl_context(term_t role, term_t config, term_t options, term_t method)
{ atom_t a;
  PL_SSL *conf;
  int r;
  term_t tail;
  term_t head = PL_new_term_ref();
  module_t module = NULL;
  atom_t method_name;
  const SSL_METHOD *ssl_method = NULL;

  PL_strip_module(options, &module, options);
  tail = PL_copy_term_ref(options);

  if ( !PL_get_atom_ex(role, &a) )
    return FALSE;
  if ( a == ATOM_server )
    r = PL_SSL_SERVER;
  else if ( a == ATOM_client )
    r = PL_SSL_CLIENT;
  else
    return PL_domain_error("ssl_role", role);

  if (!PL_get_atom(method, &method_name))
     return PL_domain_error("ssl_method", method);
  if (method_name == ATOM_sslv3)
    ssl_method = SSLv3_method();
#ifdef HAVE_SSLV2_METHOD
  else if (method_name == ATOM_sslv2)
    ssl_method = SSLv2_method();
#endif
#ifdef SSL_OP_NO_TLSv1
  else if (method_name == ATOM_tlsv1)
    ssl_method = TLSv1_method();
#endif
#ifdef SSL_OP_NO_TLSv1_1
  else if (method_name == ATOM_tlsv1_1)
    ssl_method = TLSv1_1_method();
#endif
#ifdef SSL_OP_NO_TLSv1_2
  else if (method_name == ATOM_tlsv1_2)
    ssl_method = TLSv1_2_method();
#endif
  else if (method_name == ATOM_sslv23)
    ssl_method = SSLv23_method();
  else
    return PL_domain_error("ssl_method", method);

  if ( !(conf = ssl_init(r, ssl_method)) )
    return PL_resource_error("memory");
  while( PL_get_list(tail, head, tail) )
  { atom_t name;
    int arity;

    if ( !PL_get_name_arity(head, &name, &arity) )
      return PL_type_error("ssl_option", head);

    if ( name == ATOM_password && arity == 1 )
    { char *s;

      if ( !get_char_arg(1, head, &s) )
	return FALSE;

      ssl_set_password(conf, s);
    } else if ( name == ATOM_cert && arity == 1 )
    { int val;

      if ( !get_bool_arg(1, head, &val) )
	return FALSE;

      ssl_set_cert(conf, val);
    } else if ( name == ATOM_peer_cert && arity == 1 )
    { int val;

      if ( !get_bool_arg(1, head, &val) )
	return FALSE;

      ssl_set_peer_cert(conf, val);
    } else if ( name == ATOM_cacert_file && arity == 1 )
    { term_t val = PL_new_term_ref();
      char *file;

      _PL_get_arg(1, head, val);
      if ( PL_is_functor(val, FUNCTOR_system1) )
      { _PL_get_arg(1, val, val);
	atom_t a;

	if ( !PL_get_atom_ex(val, &a) )
	  return FALSE;
	if ( a == ATOM_root_certificates )
	  ssl_set_use_system_cacert(conf, TRUE);
	else
	  return PL_domain_error("system_cacert", val);
      } else if ( PL_get_file_name(val, &file, PL_FILE_EXIST) )
      { ssl_set_cacert(conf, file);
      } else
	return FALSE;
    } else if ( name == ATOM_certificate_file && arity == 1 )
    { char *file;

      if ( !get_file_arg(1, head, &file) )
	return FALSE;

      ssl_set_certf(conf, file);
    } else if ( name == ATOM_key_file && arity == 1 )
    { char *file;

      if ( !get_file_arg(1, head, &file) )
	return FALSE;

      ssl_set_keyf(conf, file);
    } else if ( name == ATOM_pem_password_hook && arity == 1 )
    { predicate_t hook;

      if ( !get_predicate_arg(1, module, head, 2, &hook) )
	return FALSE;

      ssl_set_cb_pem_passwd(conf, pl_pem_passwd_hook, (void *)hook);
    } else if ( name == ATOM_cert_verify_hook && arity == 1 )
    { predicate_t hook;

      if ( !get_predicate_arg(1, module, head, 5, &hook) )
	return FALSE;

      ssl_set_cb_cert_verify(conf, pl_cert_verify_hook, (void *)hook);
    } else if ( name == ATOM_close_parent && arity == 1 )
    { int val;

      if ( !get_bool_arg(1, head, &val) )
	return FALSE;

      ssl_set_close_parent(conf, val);
    } else if ( name == ATOM_disable_ssl_methods && arity == 1 )
    { term_t opt_head = PL_new_term_ref();
      term_t opt_tail = PL_new_term_ref();
      int options = 0;
      _PL_get_arg(1, head, opt_tail);
      while( PL_get_list(opt_tail, opt_head, opt_tail) )
      {  atom_t option_name;
         if (!PL_get_atom(opt_head, &option_name))
            return FALSE;
         if (option_name == ATOM_sslv2)
            options |= SSL_OP_NO_SSLv2;
         else if (option_name == ATOM_sslv23)
            options |= SSL_OP_NO_SSLv3 | SSL_OP_NO_SSLv2;
         else if (option_name == ATOM_sslv3)
            options |= SSL_OP_NO_SSLv3;
#ifdef SSL_OP_NO_TLSv1
         else if (option_name == ATOM_tlsv1)
            options |= SSL_OP_NO_TLSv1;
#endif
#ifdef SSL_OP_NO_TLSv1_1
         else if (option_name == ATOM_tlsv1_1)
            options |= SSL_OP_NO_TLSv1_1;
#endif
#ifdef SSL_OP_NO_TLSv1_2
         else if (option_name == ATOM_tlsv1_2)
            options |= SSL_OP_NO_TLSv1_2;
#endif
      }

      ssl_set_method_options(conf, options);
    } else
      continue;
  }

  if ( !PL_get_nil_ex(tail) )
    return FALSE;

  return ssl_config(conf, options) && register_conf(config, conf);
}


static int
pl_ssl_close(void *handle)
{ PL_SSL_INSTANCE *instance = handle;

  assert(instance->close_needed > 0);

  if ( --instance->close_needed == 0 )
    return ssl_close(instance);

  return 0;
}


static int
pl_ssl_control(void *handle, int action, void *data)
{ PL_SSL_INSTANCE *instance = handle;

  switch(action)
  {
#ifdef __WINDOWS__
    case SIO_GETFILENO:
      return -1;
    case SIO_GETWINSOCK:
      { if (instance->sread != NULL)
        { (*instance->sread->functions->control)(instance->sread->handle,
                                                 SIO_GETWINSOCK,
                                                 data);
          return 0;
        } else if (instance->swrite != NULL)
        { (*instance->swrite->functions->control)(instance->swrite->handle,
                                                  SIO_GETWINSOCK,
                                                  data);
          return 0;
        }
      }
      return -1;
#else
    case SIO_GETFILENO:
      { if (instance->sread != NULL)
        {  SOCKET fd = Sfileno(instance->sread);
           SOCKET *fdp = data;
           *fdp = fd;
           return 0;
        } else if (instance->swrite != NULL)
        {  SOCKET fd = Sfileno(instance->swrite);
           SOCKET *fdp = data;
           *fdp = fd;
           return 0;
        }
      }
      return -1;
#endif
    case SIO_SETENCODING:
    case SIO_FLUSHOUTPUT:
      return 0;
    default:
      return -1;
  }
}



static foreign_t
pl_ssl_exit(term_t config)
{
  /* This is now handled by GC and this predicate does nothing.
     See release_ssl()
  */
  PL_succeed;
}


static IOFUNCTIONS ssl_funcs =
{ ssl_read,				/* read */
  ssl_write,				/* write */
  NULL,					/* seek */
  pl_ssl_close,				/* close */
  pl_ssl_control			/* control */
};


static foreign_t
pl_ssl_put_socket(term_t config, term_t data)
{ PL_SSL *conf;
  if ( !get_conf(config, &conf) )
    return FALSE;
  return PL_get_integer(data, &conf->sock);
}

static foreign_t
pl_ssl_get_socket(term_t config, term_t data)
{ PL_SSL *conf;
  if ( !get_conf(config, &conf) )
    return FALSE;
  return PL_unify_integer(data, conf->sock);
}

/**
 * FIXME: if anything goes wrong, the instance is not reclaimed.
 * Can we simple call free() on it?
 */
static foreign_t
pl_ssl_negotiate(term_t config,
		 term_t org_in, term_t org_out, /* wire streams */
		 term_t in, term_t out)		/* data streams */
{ PL_SSL *conf;
  IOSTREAM *sorg_in, *sorg_out;
  IOSTREAM *i, *o;
  PL_SSL_INSTANCE * instance = NULL;
  int rc;

  if ( !get_conf(config, &conf) )
    return FALSE;
  if ( !PL_get_stream_handle(org_in, &sorg_in) )
    return FALSE;
  if ( !PL_get_stream_handle(org_out, &sorg_out) )
    return FALSE;

  if ( !(rc = ssl_ssl_bio(conf, sorg_in, sorg_out, &instance)) )
  { PL_release_stream(sorg_in);
    PL_release_stream(sorg_out);
    return raise_ssl_error(ERR_get_error());
  }

  if ( !(i=Snew(instance, SIO_INPUT|SIO_RECORDPOS|SIO_FBUF, &ssl_funcs)) )
  { PL_release_stream(sorg_in);
    PL_release_stream(sorg_out);
    return PL_resource_error("memory");
  }
  instance->close_needed++;
  if ( !PL_unify_stream(in, i) )
  { Sclose(i);
    PL_release_stream(sorg_in);
    PL_release_stream(sorg_out);
    return FALSE;
  }
  Sset_filter(sorg_in, i);
  PL_release_stream(sorg_in);
  instance->dread = i;

  if ( !(o=Snew(instance, SIO_OUTPUT|SIO_RECORDPOS|SIO_FBUF, &ssl_funcs)) )
  { PL_release_stream(sorg_out);
    return PL_resource_error("memory");
  }
  instance->close_needed++;
  if ( !PL_unify_stream(out, o) )
  { Sclose(i);
    Sset_filter(sorg_in, NULL);
    PL_release_stream(sorg_out);
    Sclose(o);
    return FALSE;
  }
  Sset_filter(sorg_out, o);
  PL_release_stream(sorg_out);
  instance->dwrite = o;

  /* Increase atom reference count so that the context is not
     GCd until this session is complete */
  ssl_deb(4, "Increasing count on %d\n", conf->atom);
  PL_register_atom(conf->atom);
  return TRUE;
}

static foreign_t
pl_rsa_private_decrypt(term_t private_t, term_t cipher_t, term_t plain_t)
{ size_t cipher_length;
  unsigned char* cipher;
  unsigned char* plain;
  int outsize;
  RSA* key;
  int retval;

  if( !PL_get_nchars(cipher_t, &cipher_length, (char**)&cipher,
		     CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION) )
    return FALSE;
  if ( !recover_private_key(private_t, &key) )
    return FALSE;

  outsize = RSA_size(key);
  ssl_deb(1, "Output size is going to be %d", outsize);
  plain = PL_malloc(outsize);
  ssl_deb(1, "Allocated %d bytes for plaintext", outsize);
  if ((outsize = RSA_private_decrypt((int)cipher_length, cipher, plain, key, RSA_PKCS1_PADDING)) <= 0)
  { ssl_deb(1, "Failure to decrypt!");
    RSA_free(key);
    PL_free(plain);
    PL_fail;
  }
  ssl_deb(1, "decrypted bytes: %d", outsize);
  ssl_deb(1, "Freeing RSA");
  RSA_free(key);
  ssl_deb(1, "Assembling plaintext");
  retval = PL_unify_chars(plain_t, PL_STRING|REP_ISO_LATIN_1,
			  outsize, (char*)plain);
  ssl_deb(1, "Freeing plaintext");
  PL_free(plain);
  ssl_deb(1, "Done");
  return retval;
}

static foreign_t
pl_rsa_public_decrypt(term_t public_t, term_t cipher_t, term_t plain_t)
{ size_t cipher_length;
  unsigned char* cipher;
  unsigned char* plain;
  int outsize;
  RSA* key;
  int retval;

  if ( !PL_get_nchars(cipher_t, &cipher_length, (char**)&cipher,
		      CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION) )
    return FALSE;
  if (!recover_public_key(public_t, &key))
    return FALSE;

  outsize = RSA_size(key);
  ssl_deb(1, "Output size is going to be %d", outsize);
  plain = PL_malloc(outsize);
  ssl_deb(1, "Allocated %d bytes for plaintext", outsize);
  if ((outsize = RSA_public_decrypt((int)cipher_length, cipher, plain, key, RSA_PKCS1_PADDING)) <= 0)
  { ssl_deb(1, "Failure to decrypt!");
    RSA_free(key);
    PL_free(plain);
    return FALSE;
  }
  ssl_deb(1, "decrypted bytes: %d", outsize);
  ssl_deb(1, "Freeing RSA");
  RSA_free(key);
  ssl_deb(1, "Assembling plaintext");
  retval = PL_unify_chars(plain_t, PL_STRING|REP_ISO_LATIN_1,
			  outsize, (char*)plain);
  ssl_deb(1, "Freeing plaintext");
  PL_free(plain);
  ssl_deb(1, "Done");
  return retval;
}

static foreign_t
pl_rsa_public_encrypt(term_t public_t, term_t plain_t, term_t cipher_t)
{ size_t plain_length;
  unsigned char* cipher;
  unsigned char* plain;
  int outsize;
  RSA* key;
  int retval;

  ssl_deb(1, "Generating terms");
  ssl_deb(1, "Collecting plaintext");
  if ( !PL_get_nchars(plain_t, &plain_length, (char**)&plain,
		      CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION) )
     return FALSE;
  if (!recover_public_key(public_t, &key))
     return FALSE;

  outsize = RSA_size(key);
  ssl_deb(1, "Output size is going to be %d\n", outsize);
  cipher = PL_malloc(outsize);
  ssl_deb(1, "Allocated %d bytes for ciphertext\n", outsize);
  if ((outsize = RSA_public_encrypt((int)plain_length, plain, cipher, key, RSA_PKCS1_PADDING)) <= 0)
  { ssl_deb(1, "Failure to encrypt!");
    PL_free(cipher);
    RSA_free(key);
    return FALSE;
  }
  ssl_deb(1, "encrypted bytes: %d\n", outsize);
  ssl_deb(1, "Freeing RSA");
  RSA_free(key);
  ssl_deb(1, "Assembling plaintext");
  retval = PL_unify_chars(cipher_t, PL_STRING|REP_ISO_LATIN_1,
			  outsize, (char*)cipher);
  ssl_deb(1, "Freeing plaintext");
  PL_free(cipher);
  ssl_deb(1, "Done");
  return retval;
}


static foreign_t
pl_rsa_private_encrypt(term_t private_t, term_t plain_t, term_t cipher_t)
{ size_t plain_length;
  unsigned char* cipher;
  unsigned char* plain;
  int outsize;
  RSA* key;
  int retval;
  if ( !PL_get_nchars(plain_t, &plain_length, (char**)&plain,
		      CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION))
    return FALSE;
  if (!recover_private_key(private_t, &key))
    return FALSE;

  outsize = RSA_size(key);
  ssl_deb(1, "Output size is going to be %d", outsize);
  cipher = PL_malloc(outsize);
  ssl_deb(1, "Allocated %d bytes for ciphertext", outsize);
  if ((outsize = RSA_private_encrypt((int)plain_length, plain, cipher, key, RSA_PKCS1_PADDING)) <= 0)
  { ssl_deb(1, "Failure to encrypt!");
    PL_free(cipher);
    RSA_free(key);
    return FALSE;
  }
  ssl_deb(1, "encrypted bytes: %d", outsize);
  ssl_deb(1, "Freeing RSA");
  RSA_free(key);
  ssl_deb(1, "Assembling plaintext");
  retval = PL_unify_chars(cipher_t, PL_STRING|REP_ISO_LATIN_1,
			  outsize, (char*)cipher);
  ssl_deb(1, "Freeing plaintext");
  PL_free(cipher);
  ssl_deb(1, "Done");
  return retval;
}


static foreign_t
pl_ssl_debug(term_t level)
{ int l;

  if ( !PL_get_integer_ex(level, &l) )
    return FALSE;

  ssl_set_debug(l);

  return TRUE;
}


static int
add_key_string(term_t list, functor_t f, size_t len, const unsigned char*s)
{ term_t tmp;
  int rc;

  rc = ( (tmp = PL_new_term_refs(2)) &&
	 PL_unify_list_ex(list, tmp+0, list) &&
	 PL_put_string_nchars(tmp+1, len, (const char*)s) &&
	 PL_unify_term(tmp+0, PL_FUNCTOR, f, PL_TERM, tmp+1)
       );
  if ( tmp )
    PL_reset_term_refs(tmp);
  return rc;
}


static foreign_t
pl_ssl_session(term_t stream_t, term_t session_t)
{ IOSTREAM* stream;
  PL_SSL_INSTANCE* instance;
  SSL* ssl;
  SSL_SESSION* session;
  term_t list_t = PL_copy_term_ref(session_t);
  term_t node_t = PL_new_term_ref();

  if ( !PL_get_stream_handle(stream_t, &stream) )
     return FALSE;
  if ( stream->functions != &ssl_funcs )
  { PL_release_stream(stream);
    return PL_domain_error("ssl_stream", stream_t);
  }

  instance = stream->handle;
  PL_release_stream(stream);

  if ( !(ssl = instance->ssl) ||
       !(session = SSL_get_session(ssl)) )
    return PL_existence_error("ssl_session", stream_t);

  if ( !PL_unify_list_ex(list_t, node_t, list_t) )
    return FALSE;
  if ( !PL_unify_term(node_t,
		      PL_FUNCTOR, FUNCTOR_version1,
		      PL_INTEGER, (int)session->ssl_version))
    return FALSE;

  if ( !add_key_string(list_t, FUNCTOR_session_key1,
		       session->key_arg_length, session->key_arg) )
    return FALSE;

  if ( !add_key_string(list_t, FUNCTOR_master_key1,
		       session->master_key_length, session->master_key) )
    return FALSE;

  if ( !add_key_string(list_t, FUNCTOR_session_id1,
		       session->session_id_length, session->session_id) )
    return FALSE;

  if ( ssl->s3 != NULL ) /* If the connection is SSLv2?! */
  { if ( !add_key_string(list_t, FUNCTOR_client_random1,
			 SSL3_RANDOM_SIZE, ssl->s3->client_random) )
      return FALSE;

    if ( !add_key_string(list_t, FUNCTOR_server_random1,
			 SSL3_RANDOM_SIZE, ssl->s3->server_random) )
      return FALSE;
  }

  return PL_unify_nil_ex(list_t);
}


static foreign_t
pl_system_root_certificates(term_t list)
{ X509_list *certs;
  term_t head = PL_new_term_ref();
  term_t tail = PL_copy_term_ref(list);

  if ( !(certs=system_root_certificates()) )
    return PL_unify_nil(list);

  for(; certs; certs = certs->next)
  { if ( !(PL_unify_list(tail, head, tail) &&
	   unify_certificate(head, certs->cert)))
    { return FALSE;
    }
  }

  return PL_unify_nil(tail);
}

static foreign_t
pl_ssl_peer_certificate(term_t stream_t, term_t Cert)
{ IOSTREAM* stream;
  PL_SSL_INSTANCE* instance;
  X509 *cert;

  if ( !PL_get_stream_handle(stream_t, &stream) )
    return FALSE;
  if ( stream->functions != &ssl_funcs )
  { PL_release_stream(stream);
    return PL_domain_error("ssl_stream", stream_t);
  }

  instance = stream->handle;
  PL_release_stream(stream);
  if ( (cert = ssl_peer_certificate(instance)) )
  { return unify_certificate(Cert, cert);
  }

  return FALSE;
}


		 /*******************************
		 *	     INSTALL		*
		 *******************************/


install_t
install_ssl4pl()
{ ATOM_server             = PL_new_atom("server");
  ATOM_client             = PL_new_atom("client");
  ATOM_password           = PL_new_atom("password");
  ATOM_cert               = PL_new_atom("cert");
  ATOM_peer_cert          = PL_new_atom("peer_cert");
  ATOM_cacert_file        = PL_new_atom("cacert_file");
  ATOM_certificate_file   = PL_new_atom("certificate_file");
  ATOM_key_file           = PL_new_atom("key_file");
  ATOM_pem_password_hook  = PL_new_atom("pem_password_hook");
  ATOM_cert_verify_hook   = PL_new_atom("cert_verify_hook");
  ATOM_close_parent       = PL_new_atom("close_parent");
  ATOM_disable_ssl_methods= PL_new_atom("disable_ssl_methods");
  ATOM_root_certificates  = PL_new_atom("root_certificates");
  ATOM_sslv2              = PL_new_atom("sslv2");
  ATOM_sslv23             = PL_new_atom("sslv23");
  ATOM_sslv3              = PL_new_atom("sslv3");
  ATOM_tlsv1              = PL_new_atom("tlsv1");
  ATOM_tlsv1_1            = PL_new_atom("tlsv1_1");
  ATOM_tlsv1_2            = PL_new_atom("tlsv1_2");
  ATOM_minus		  = PL_new_atom("-");

  FUNCTOR_error2          = PL_new_functor(PL_new_atom("error"), 2);
  FUNCTOR_ssl_error4      = PL_new_functor(PL_new_atom("ssl_error"), 4);
  FUNCTOR_permission_error3=PL_new_functor(PL_new_atom("permission_error"), 3);
  FUNCTOR_ip4		  = PL_new_functor(PL_new_atom("ip"), 4);
  FUNCTOR_version1	  = PL_new_functor(PL_new_atom("version"), 1);
  FUNCTOR_notbefore1	  = PL_new_functor(PL_new_atom("notbefore"), 1);
  FUNCTOR_notafter1	  = PL_new_functor(PL_new_atom("notafter"), 1);
  FUNCTOR_subject1	  = PL_new_functor(PL_new_atom("subject"), 1);
  FUNCTOR_issuername1	  = PL_new_functor(PL_new_atom("issuer_name"), 1);
  FUNCTOR_serial1	  = PL_new_functor(PL_new_atom("serial"), 1);
  FUNCTOR_key1	          = PL_new_functor(PL_new_atom("key"), 1);
  FUNCTOR_public_key1     = PL_new_functor(PL_new_atom("public_key"), 1);
  FUNCTOR_private_key1    = PL_new_functor(PL_new_atom("private_key"), 1);
  FUNCTOR_rsa8		  = PL_new_functor(PL_new_atom("rsa"), 8);
  FUNCTOR_hash1	          = PL_new_functor(PL_new_atom("hash"), 1);
  FUNCTOR_next_update1    = PL_new_functor(PL_new_atom("next_update"), 1);
  FUNCTOR_signature1      = PL_new_functor(PL_new_atom("signature"), 1);
  FUNCTOR_equals2         = PL_new_functor(PL_new_atom("="), 2);
  FUNCTOR_crl1            = PL_new_functor(PL_new_atom("crl"), 1);
  FUNCTOR_revoked2        = PL_new_functor(PL_new_atom("revoked"), 2);
  FUNCTOR_revocations1    = PL_new_functor(PL_new_atom("revocations"), 1);
  FUNCTOR_session_key1    = PL_new_functor(PL_new_atom("session_key"), 1);
  FUNCTOR_master_key1     = PL_new_functor(PL_new_atom("master_key"), 1);
  FUNCTOR_session_id1     = PL_new_functor(PL_new_atom("session_id"), 1);
  FUNCTOR_client_random1  = PL_new_functor(PL_new_atom("client_random"), 1);
  FUNCTOR_server_random1  = PL_new_functor(PL_new_atom("server_random"), 1);
  FUNCTOR_system1         = PL_new_functor(PL_new_atom("system"), 1);
  FUNCTOR_unsupported_hash_algorithm1 = PL_new_functor(PL_new_atom("unsupported_hash_algorithm"), 1);

  PL_register_foreign("_ssl_context",	4, pl_ssl_context,    0);
  PL_register_foreign("_ssl_exit",	1, pl_ssl_exit,	      0);
  PL_register_foreign("ssl_put_socket",	2, pl_ssl_put_socket, 0);
  PL_register_foreign("ssl_get_socket",	2, pl_ssl_get_socket, 0);
  PL_register_foreign("ssl_negotiate",	5, pl_ssl_negotiate,  0);
  PL_register_foreign("ssl_debug",	1, pl_ssl_debug,      0);
  PL_register_foreign("ssl_session",    2, pl_ssl_session,    0);
  PL_register_foreign("ssl_peer_certificate",
					2, pl_ssl_peer_certificate, 0);
  PL_register_foreign("load_crl",       2, pl_load_crl,      0);
  PL_register_foreign("load_certificate",2,pl_load_certificate,      0);
  PL_register_foreign("load_private_key",3,pl_load_private_key,      0);
  PL_register_foreign("load_public_key", 2,pl_load_public_key,      0);
  PL_register_foreign("rsa_private_decrypt", 3, pl_rsa_private_decrypt, 0);
  PL_register_foreign("rsa_private_encrypt", 3, pl_rsa_private_encrypt, 0);
  PL_register_foreign("rsa_public_decrypt", 3, pl_rsa_public_decrypt, 0);
  PL_register_foreign("rsa_public_encrypt", 3, pl_rsa_public_encrypt, 0);
  PL_register_foreign("system_root_certificates", 1, pl_system_root_certificates, 0);

  /*
   * Initialize ssllib
   */
  (void) ssl_lib_init();
}

install_t
uninstall_ssl4pl()
{ ssl_lib_exit();
}
