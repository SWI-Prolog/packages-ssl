/*  Part of SWI-Prolog

    Author:        Matt Lilley and Markus Triska
    WWW:           http://www.swi-prolog.org
    Copyright (c)  2004-2016, SWI-Prolog Foundation
                              VU University Amsterdam
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
#include <SWI-Stream.h>
#include <SWI-Prolog.h>
#include <assert.h>
#include <string.h>
#include "cryptolib.h"

static atom_t ATOM_sslv23;
static atom_t ATOM_minus;			/* "-" */
static atom_t ATOM_text;
static atom_t ATOM_octet;
static atom_t ATOM_utf8;

static atom_t ATOM_sha1;
static atom_t ATOM_sha224;
static atom_t ATOM_sha256;
static atom_t ATOM_sha384;
static atom_t ATOM_sha512;

static atom_t ATOM_pkcs;
static atom_t ATOM_pkcs_oaep;
static atom_t ATOM_none;
static atom_t ATOM_block;
static atom_t ATOM_encoding;
static atom_t ATOM_padding;

static functor_t FUNCTOR_public_key1;
static functor_t FUNCTOR_private_key1;

typedef enum
{ RSA_MODE, EVP_MODE
} crypt_mode_t;


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
recover_rsa(term_t t, RSA** rsap)
{ RSA *rsa = RSA_new();

#if OPENSSL_VERSION_NUMBER < 0x10100000L
  if ( get_bn_arg(1, t, &rsa->n) &&
       get_bn_arg(2, t, &rsa->e) &&
       get_bn_arg(3, t, &rsa->d) &&
       get_bn_arg(4, t, &rsa->p) &&
       get_bn_arg(5, t, &rsa->q) &&
       get_bn_arg(6, t, &rsa->dmp1) &&
       get_bn_arg(7, t, &rsa->dmq1) &&
       get_bn_arg(8, t, &rsa->iqmp)
     )
  {
#else
  BIGNUM *n = NULL, *e = NULL, *d = NULL, *p = NULL,
    *q = NULL, *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;

  if ( get_bn_arg(1, t, &n) &&
       get_bn_arg(2, t, &e) &&
       get_bn_arg(3, t, &d) &&
       get_bn_arg(4, t, &p) &&
       get_bn_arg(5, t, &q) &&
       get_bn_arg(6, t, &dmp1) &&
       get_bn_arg(7, t, &dmq1) &&
       get_bn_arg(8, t, &iqmp) )
  {
    if ( !RSA_set0_key(rsa, n, e, d) ||
         ( (p || q) && !RSA_set0_factors(rsa, p, q) ) ||
         ( (dmp1 || dmq1 || iqmp) &&
           !RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp)) )
    { RSA_free(rsa);
      return FALSE;
    }
#endif
    *rsap = rsa;
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


		 /*******************************
		 *       RSA ENCRYPT/DECRYPT	*
		 *******************************/

static int
get_text_representation(term_t t, int *rep)
{ atom_t a;

  if ( PL_get_atom_ex(t, &a) )
  { if      ( a == ATOM_octet ) *rep = REP_ISO_LATIN_1;
    else if ( a == ATOM_utf8  ) *rep = REP_UTF8;
    else if ( a == ATOM_text  ) *rep = REP_MB;
    else return PL_domain_error("encoding", t);

    return TRUE;
  }

  return FALSE;
}

static int
get_padding(term_t t, crypt_mode_t mode, int *padding)
{ atom_t a;

  if ( PL_get_atom_ex(t, &a) )
  { if      ( a == ATOM_pkcs && mode == RSA_MODE )       *padding = RSA_PKCS1_PADDING;
    else if ( a == ATOM_pkcs_oaep && mode == RSA_MODE  ) *padding = RSA_PKCS1_OAEP_PADDING;
    else if ( a == ATOM_none && mode == RSA_MODE  )      *padding = RSA_NO_PADDING;
    else if ( a == ATOM_sslv23  && mode == RSA_MODE )    *padding = RSA_SSLV23_PADDING;
    else if ( a == ATOM_none  && mode == EVP_MODE )      *padding = 0;
    else if ( a == ATOM_block  && mode == EVP_MODE )     *padding = 1;
    else return PL_domain_error("padding", t);

    return TRUE;
  }

  return FALSE;
}


static int
get_enc_text(term_t text, term_t enc, size_t *len, unsigned char **data)
{ int flags;

  if ( get_text_representation(enc, &flags) )
  { flags |= CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION;
    return PL_get_nchars(text, len, (char**)data, flags);
  }

  return FALSE;
}


static int
parse_options(term_t options_t, crypt_mode_t mode, int* rep, int* padding)
{ if (PL_is_atom(options_t)) /* Is really an encoding */
  { if (rep == NULL)
      return TRUE;
    else if ( !get_text_representation(options_t, rep) )
      return FALSE;
  } else
  { term_t tail = PL_copy_term_ref(options_t);
    term_t head = PL_new_term_ref();

    while( PL_get_list_ex(tail, head, tail) )
    { atom_t name;
      size_t arity;
      term_t arg = PL_new_term_ref();

      if ( !PL_get_name_arity(head, &name, &arity) ||
           arity != 1 ||
           !PL_get_arg(1, head, arg) )
        return PL_type_error("option", head);

      if ( name == ATOM_encoding )
      { if ( !get_text_representation(arg, rep) )
          return FALSE;
      } else if ( name == ATOM_padding && padding != NULL)
      { if ( !get_padding(arg, mode, padding) )
        return FALSE;
      }
    }
    if ( !PL_get_nil_ex(tail) )
      return FALSE;
  }

  return TRUE;
}

static foreign_t
pl_rsa_private_decrypt(term_t private_t, term_t cipher_t,
		       term_t plain_t, term_t options_t)
{ size_t cipher_length;
  unsigned char* cipher;
  unsigned char* plain;
  int outsize;
  RSA* key;
  int rep = REP_UTF8;
  int padding = RSA_PKCS1_PADDING;
  int retval;

  if ( !parse_options(options_t, RSA_MODE, &rep, &padding))
    return FALSE;

  if( !PL_get_nchars(cipher_t, &cipher_length, (char**)&cipher,
		     CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION) )
    return FALSE;
  if ( !recover_private_key(private_t, &key) )
    return FALSE;

  outsize = RSA_size(key);
  ssl_deb(1, "Output size is going to be %d", outsize);
  plain = PL_malloc(outsize);
  ssl_deb(1, "Allocated %d bytes for plaintext", outsize);
  if ((outsize = RSA_private_decrypt((int)cipher_length, cipher,
				     plain, key, padding)) <= 0)
  { ssl_deb(1, "Failure to decrypt!");
    RSA_free(key);
    PL_free(plain);
    return raise_ssl_error(ERR_get_error());
  }
  ssl_deb(1, "decrypted bytes: %d", outsize);
  ssl_deb(1, "Freeing RSA");
  RSA_free(key);
  ssl_deb(1, "Assembling plaintext");
  retval = PL_unify_chars(plain_t, rep | PL_STRING, outsize, (char*)plain);
  ssl_deb(1, "Freeing plaintext");
  PL_free(plain);
  ssl_deb(1, "Done");

  return retval;
}

static foreign_t
pl_rsa_public_decrypt(term_t public_t, term_t cipher_t,
                      term_t plain_t, term_t options_t)
{ size_t cipher_length;
  unsigned char* cipher;
  unsigned char* plain;
  int outsize;
  RSA* key;
  int rep = REP_UTF8;
  int padding = RSA_PKCS1_PADDING;
  int retval;

  if ( !parse_options(options_t, RSA_MODE, &rep, &padding))
    return FALSE;
  if ( !PL_get_nchars(cipher_t, &cipher_length, (char**)&cipher,
		      CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION) )
    return FALSE;
  if ( !recover_public_key(public_t, &key) )
    return FALSE;

  outsize = RSA_size(key);
  ssl_deb(1, "Output size is going to be %d", outsize);
  plain = PL_malloc(outsize);
  ssl_deb(1, "Allocated %d bytes for plaintext", outsize);
  if ((outsize = RSA_public_decrypt((int)cipher_length, cipher,
                                    plain, key, padding)) <= 0)
  { ssl_deb(1, "Failure to decrypt!");
    RSA_free(key);
    PL_free(plain);
    return raise_ssl_error(ERR_get_error());
  }
  ssl_deb(1, "decrypted bytes: %d", outsize);
  ssl_deb(1, "Freeing RSA");
  RSA_free(key);
  ssl_deb(1, "Assembling plaintext");
  retval = PL_unify_chars(plain_t, rep | PL_STRING, outsize, (char*)plain);
  ssl_deb(1, "Freeing plaintext");
  PL_free(plain);
  ssl_deb(1, "Done");

  return retval;
}

static foreign_t
pl_rsa_public_encrypt(term_t public_t,
                      term_t plain_t, term_t cipher_t, term_t options_t)
{ size_t plain_length;
  unsigned char* cipher;
  unsigned char* plain;
  int outsize;
  RSA* key;
  int rep = REP_UTF8;
  int padding = RSA_PKCS1_PADDING;
  int retval;

  if ( !parse_options(options_t, RSA_MODE, &rep, &padding))
    return FALSE;

  ssl_deb(1, "Generating terms");
  ssl_deb(1, "Collecting plaintext");
  if ( !PL_get_nchars(plain_t, &plain_length, (char**)&plain,
		      CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION | rep))
    return FALSE;
  if ( !recover_public_key(public_t, &key) )
    return FALSE;

  outsize = RSA_size(key);
  ssl_deb(1, "Output size is going to be %d\n", outsize);
  cipher = PL_malloc(outsize);
  ssl_deb(1, "Allocated %d bytes for ciphertext\n", outsize);
  if ( (outsize = RSA_public_encrypt((int)plain_length, plain,
				     cipher, key, padding)) <= 0)
  { ssl_deb(1, "Failure to encrypt!");
    PL_free(cipher);
    RSA_free(key);
    return raise_ssl_error(ERR_get_error());
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
pl_rsa_private_encrypt(term_t private_t,
                       term_t plain_t, term_t cipher_t, term_t options_t)
{ size_t plain_length;
  unsigned char* cipher;
  unsigned char* plain;
  int outsize;
  RSA* key;
  int rep = REP_UTF8;
  int padding = RSA_PKCS1_PADDING;
  int retval;

  if ( !parse_options(options_t, RSA_MODE, &rep, &padding))
    return FALSE;

  if ( !PL_get_nchars(plain_t, &plain_length, (char**)&plain,
		      CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION | rep))
    return FALSE;
  if ( !recover_private_key(private_t, &key) )
    return FALSE;

  outsize = RSA_size(key);
  ssl_deb(1, "Output size is going to be %d", outsize);
  cipher = PL_malloc(outsize);
  ssl_deb(1, "Allocated %d bytes for ciphertext", outsize);
  if ((outsize = RSA_private_encrypt((int)plain_length, plain,
                                     cipher, key, padding)) <= 0)
  { ssl_deb(1, "Failure to encrypt!");
    PL_free(cipher);
    RSA_free(key);
    return raise_ssl_error(ERR_get_error());
  }
  ssl_deb(1, "encrypted bytes: %d", outsize);
  ssl_deb(1, "Freeing RSA");
  RSA_free(key);
  ssl_deb(1, "Assembling plaintext");
  retval = PL_unify_chars(cipher_t, PL_STRING|REP_ISO_LATIN_1,
			  outsize, (char*)cipher);
  ssl_deb(1, "Freeing cipher");
  PL_free(cipher);
  ssl_deb(1, "Done");

  return retval;
}


static int
get_digest_type(term_t t, int *type)
{ atom_t a;

  if ( PL_get_atom_ex(t, &a) )
  { if      ( a == ATOM_sha1   ) *type = NID_sha1;
    else if ( a == ATOM_sha224 ) *type = NID_sha224;
    else if ( a == ATOM_sha256 ) *type = NID_sha256;
    else if ( a == ATOM_sha384 ) *type = NID_sha384;
    else if ( a == ATOM_sha512 ) *type = NID_sha512;
    else
    { PL_domain_error("digest_type", t);
      return FALSE;
    }

    return TRUE;
  }

  return FALSE;
}


static foreign_t
pl_rsa_sign(term_t Private, term_t Type, term_t Enc,
	    term_t Data, term_t Signature)
{ unsigned char *data;
  size_t data_len;
  RSA *key;
  unsigned char *signature;
  unsigned int signature_len;
  int rc;
  int type;

  if ( !get_enc_text(Data, Enc, &data_len, &data) ||
       !recover_private_key(Private, &key) ||
       !get_digest_type(Type, &type) )
    return FALSE;

  signature_len = RSA_size(key);
  signature = PL_malloc(signature_len);
  rc = RSA_sign(type,
		data, (unsigned int)data_len,
		signature, &signature_len, key);
  RSA_free(key);
  if ( rc != 1 )
  { PL_free(signature);
    return raise_ssl_error(ERR_get_error());
  }
  rc = PL_unify_chars(Signature, PL_STRING|REP_ISO_LATIN_1,
		      signature_len, (char*)signature);
  PL_free(signature);

  return rc;
}

static foreign_t
pl_rsa_verify(term_t Public, term_t Type, term_t Enc,
	    term_t Data, term_t Signature)
{ unsigned char *data;
  size_t data_len;
  RSA *key;
  unsigned char *signature;
  size_t signature_len;
  int rc;
  int type;

  if ( !get_enc_text(Data, Enc, &data_len, &data) ||
       !recover_public_key(Public, &key) ||
       !get_digest_type(Type, &type) ||
       !PL_get_nchars(Signature, &signature_len, (char**)&signature, CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION) )
    return FALSE;

  rc = RSA_verify(type,
                  data, (unsigned int)data_len,
                  signature, (unsigned int)signature_len, key);
  RSA_free(key);
  if ( rc != 1 )
  { return raise_ssl_error(ERR_get_error());
  }
  return 1;
}



#ifndef HAVE_EVP_CIPHER_CTX_RESET
#define EVP_CIPHER_CTX_reset(C) EVP_CIPHER_CTX_init(C)
#endif

static foreign_t
pl_evp_decrypt(term_t ciphertext_t, term_t algorithm_t,
	       term_t key_t, term_t iv_t, term_t plaintext_t,
	       term_t options_t)
{ EVP_CIPHER_CTX* ctx = NULL;
  const EVP_CIPHER *cipher;
  char* key;
  char* iv;
  char* ciphertext;
  size_t cipher_length;
  int plain_length;
  char* algorithm;
  char* plaintext;
  int cvt_flags = CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION;
  int rep = REP_UTF8;
  int padding = 1;

  if ( !parse_options(options_t, EVP_MODE, &rep, &padding))
    return FALSE;

  if ( !PL_get_chars(key_t, &key, cvt_flags) ||
       !PL_get_chars(iv_t, &iv, cvt_flags) ||
       !PL_get_nchars(ciphertext_t, &cipher_length, &ciphertext, cvt_flags) ||
       !PL_get_chars(algorithm_t, &algorithm, cvt_flags) )
    return FALSE;

  if ( (cipher = EVP_get_cipherbyname(algorithm)) == NULL )
    return PL_domain_error("cipher", algorithm_t);
  if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
    return FALSE;

  EVP_CIPHER_CTX_reset(ctx);
  EVP_DecryptInit_ex(ctx, cipher, NULL,
		     (const unsigned char*)key, (const unsigned char*)iv);
  EVP_CIPHER_CTX_set_padding(ctx, padding);
  plaintext = PL_malloc(cipher_length + EVP_CIPHER_block_size(cipher));
  if ( EVP_DecryptUpdate(ctx, (unsigned char*)plaintext, &plain_length,
			 (unsigned char*)ciphertext, cipher_length) == 1 )
  { int last_chunk = plain_length;
    int rc;
    rc = EVP_DecryptFinal_ex(ctx, (unsigned char*)(plaintext + plain_length),
                              &last_chunk);
    EVP_CIPHER_CTX_free(ctx);
    ERR_print_errors_fp(stderr);
    rc &= PL_unify_chars(plaintext_t, rep | PL_STRING, plain_length + last_chunk,
                         plaintext);
    PL_free(plaintext);
    return rc;
  }

  PL_free(plaintext);
  EVP_CIPHER_CTX_free(ctx);

  return FALSE;
}

static foreign_t
pl_evp_encrypt(term_t plaintext_t, term_t algorithm_t,
               term_t key_t, term_t iv_t, term_t ciphertext_t,
	       term_t options_t)
{ EVP_CIPHER_CTX* ctx = NULL;
  const EVP_CIPHER *cipher;
  char* key;
  char* iv;
  char* ciphertext;
  int cipher_length;
  char* algorithm;
  char* plaintext;
  size_t plain_length;
  int cvt_flags = CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION;
  int rep = REP_UTF8;

  if ( !parse_options(options_t, EVP_MODE, &rep, NULL))
    return FALSE;

  if ( !PL_get_chars(key_t, &key, cvt_flags) ||
       !PL_get_chars(iv_t, &iv, cvt_flags) ||
       !PL_get_nchars(plaintext_t, &plain_length, &plaintext, cvt_flags | rep) ||
       !PL_get_chars(algorithm_t, &algorithm, cvt_flags) )
    return FALSE;

  if ( (cipher = EVP_get_cipherbyname(algorithm)) == NULL )
    return PL_domain_error("cipher", algorithm_t);
  if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
    return FALSE;

  EVP_CIPHER_CTX_reset(ctx);
  EVP_EncryptInit_ex(ctx, cipher, NULL,
		     (const unsigned char*)key, (const unsigned char*)iv);

  ciphertext = PL_malloc(plain_length + EVP_CIPHER_block_size(cipher));
  if ( EVP_EncryptUpdate(ctx, (unsigned char*)ciphertext, &cipher_length,
                         (unsigned char*)plaintext, plain_length) == 1 )
  { int last_chunk;
    int rc;

    EVP_EncryptFinal_ex(ctx, (unsigned char*)(ciphertext + cipher_length),
			&last_chunk);
    EVP_CIPHER_CTX_free(ctx);
    rc = PL_unify_chars(ciphertext_t,  PL_STRING|REP_ISO_LATIN_1,
			cipher_length + last_chunk, ciphertext);
    PL_free(ciphertext);
    return rc;
  }

  PL_free(ciphertext);
  EVP_CIPHER_CTX_free(ctx);

  return FALSE;
}

		 /***************************
		 *         MD5 HASH         *
		 ****************************/

typedef struct
{ unsigned int  encoding;
} optval;


static int
md5_options(term_t options, optval *result)
{ term_t opts = PL_copy_term_ref(options);
  term_t opt = PL_new_term_ref();

					/* defaults */
  memset(result, 0, sizeof(*result));
  result->encoding = REP_UTF8;

  while(PL_get_list(opts, opt, opts))
  { atom_t aname;
    size_t arity;

    if ( PL_get_name_arity(opt, &aname, &arity) && arity == 1 )
    { term_t a = PL_new_term_ref();

      _PL_get_arg(1, opt, a);

      if ( aname == ATOM_encoding )
      { atom_t a_enc;

	if ( !PL_get_atom_ex(a, &a_enc) )
	  return FALSE;
	if ( a_enc == ATOM_utf8 )
	  result->encoding = REP_UTF8;
	else if ( a_enc == ATOM_octet )
	  result->encoding = REP_ISO_LATIN_1;
	else
	  return PL_domain_error("encoding", a);
      }
    } else
    { return PL_type_error("option", opt);
    }
  }

  if ( !PL_get_nil(opts) )
    return PL_type_error("list", opts);

  return TRUE;
}

static int
md5_unify_digest(term_t t, const unsigned char digest[16])
{ char hex_output[16*2];
  int di;
  char *pi;
  static char hexd[] = "0123456789abcdef";

  for(pi=hex_output, di = 0; di < 16; ++di)
  { *pi++ = hexd[(digest[di] >> 4) & 0x0f];
    *pi++ = hexd[digest[di] & 0x0f];
  }

  return PL_unify_atom_nchars(t, 16*2, hex_output);
}

static foreign_t
pl_md5_hash(term_t from, term_t md5, term_t options)
{
  char *data;
  size_t datalen;
  optval opts;
  unsigned char digest[16];
  unsigned int len;
  int r;
  EVP_MD_CTX *ctx;

  if ( !md5_options(options, &opts) )
    return FALSE;

  if ( !PL_get_nchars(from, &datalen, &data,
		      CVT_ATOM|CVT_STRING|CVT_LIST|CVT_EXCEPTION|opts.encoding) )
    return FALSE;

  ctx = EVP_MD_CTX_new();
  if ( !EVP_DigestInit_ex(ctx, EVP_md5(), NULL) )
  { EVP_MD_CTX_free(ctx);
    return FALSE;
  }

  EVP_DigestUpdate(ctx, data, datalen);
  EVP_DigestFinal_ex(ctx, digest, &len);
  r = md5_unify_digest(md5, digest);
  EVP_MD_CTX_free(ctx);

  return r;
}

		 /*******************************
		 *	     INSTALL		*
		 *******************************/

#define MKATOM(n) ATOM_ ## n = PL_new_atom(#n);

install_t
install_crypto4pl(void)
{
  ATOM_minus                = PL_new_atom("-");
  MKATOM(sslv23);
  MKATOM(text);
  MKATOM(octet);
  MKATOM(utf8);
  MKATOM(sha1);
  MKATOM(sha224);
  MKATOM(sha256);
  MKATOM(sha384);
  MKATOM(sha512);
  MKATOM(pkcs);
  MKATOM(pkcs_oaep);
  MKATOM(none);
  MKATOM(block);
  MKATOM(encoding);
  MKATOM(padding);

  FUNCTOR_public_key1       = PL_new_functor(PL_new_atom("public_key"), 1);
  FUNCTOR_private_key1      = PL_new_functor(PL_new_atom("private_key"), 1);

  PL_register_foreign("rsa_private_decrypt", 4, pl_rsa_private_decrypt, 0);
  PL_register_foreign("rsa_private_encrypt", 4, pl_rsa_private_encrypt, 0);
  PL_register_foreign("rsa_public_decrypt", 4, pl_rsa_public_decrypt, 0);
  PL_register_foreign("rsa_public_encrypt", 4, pl_rsa_public_encrypt, 0);
  PL_register_foreign("rsa_sign", 5, pl_rsa_sign, 0);
  PL_register_foreign("rsa_verify", 5, pl_rsa_verify, 0);
  PL_register_foreign("evp_decrypt", 6, pl_evp_decrypt, 0);
  PL_register_foreign("evp_encrypt", 6, pl_evp_encrypt, 0);
  PL_register_foreign("md5_hash", 3, pl_md5_hash, 0);

  /*
   * Initialize crypto library
   */
  (void) crypto_lib_init();

}

install_t
uninstall_crypto4pl(void)
{ crypto_lib_exit();
}
