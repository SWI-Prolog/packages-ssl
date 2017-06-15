## Introduction {#crypto-introduction}

This library provides bindings  to  functionality   of  OpenSSL  that is
related to cryptography and authentication,   not  necessarily involving
connections, sockets or streams.

## Cryptographically secure random numbers {#crypto-random}

Many cryptographic applications require the availability of numbers that
are  sufficiently unpredictable.   Examples  are the  creation of  keys,
nonces and salts.  With this library, you can generate cryptographically
strong pseudo-random numbers for such use cases:

  * [[crypto_n_random_bytes/2]]

## Hashes and digests {#crypto-hash}

A **hash**, also called **digest**, is  a way to verify the integrity of
data.  In typical  cases, a hash is significantly shorter  than the data
itself,  and already  miniscule changes  in the  data lead  to different
hashes.

The  hash functionality  of this  library subsumes  and extends  that of
`library(sha)`, `library(hash_stream)` and `library(md5)` by providing a
unified interface to all available digest algorithms.

The underlying  OpenSSL library  (`libcrypto`) is dynamically  loaded if
_either_ `library(crypto)`  or `library(ssl)` are loaded.  Therefore, if
your application uses `library(ssl)`,  you can use `library(crypto)` for
hashing without increasing the memory  footprint of your application. In
other cases, the specialised hashing  libraries are more lightweight but
less general alternatives to `library(crypto)`.

The most important predicates to compute hashes are:

  * [[crypto_data_hash/3]]
  * [[crypto_file_hash/3]]

For further reasoning and conversion of digests in hexadecimal notation,
the following bidirectional relation is provided:

  * [[hex_bytes/2]]

In addition, the  following predicates are provided  for building hashes
_incrementally_.  This  works  by  first  creating  a  **context**  with
crypto_context_new/2, then using this context with crypto_data_context/3
to  incrementally  obtain  further  contexts, and  finally  extract  the
resulting hash with crypto_context_hash/2.

  * [[crypto_context_new/2]]
  * [[crypto_data_context/3]]
  * [[crypto_context_hash/2]]

The following hashing predicates work over _streams_:

  * [[crypto_open_hash_stream/3]]
  * [[crypto_stream_hash/2]]

## Digital signatures {#crypto-signatures}

A digital **signature**  is a relation between a key  and data that only
someone who knows the key can compute.

_Signing_ uses  a _private_  key, and _verifying_  a signature  uses the
corresponding _public_ key of the  signing entity. This library supports
both  RSA  and ECDSA  signatures.  You  can use  load_private_key/3  and
load_public_key/2 to load keys from files and streams.

In typical cases, we use this mechanism  to sign the _hash_ of data. See
[hashing](<#crypto-hash>).  For this  reason,  the following  predicates
work on the _hexadecimal_ representation of  hashes that is also used by
crypto_data_hash/3 and related predicates:

  * [[ecdsa_sign/4]]
  * [[ecdsa_verify/4]]
  * [[rsa_sign/4]]
  * [[rsa_verify/4]]

Signatures are also  represented in hexadecimal notation,  and you can
use hex_bytes/2 to convert them to and from lists of bytes (integers).

## Asymmetric encryption and decryption {#crypto-asymmetric}

The  following  predicates  provide   _asymmetric_  RSA  encryption  and
decryption.  This  means that the key  that is used for  _encryption_ is
different from the one used to _decrypt_ the data:

  * [[rsa_private_decrypt/4]]

## Symmetric encryption and decryption {#crypto-symmetric}

The following predicates provide _symmetric_ encryption and decryption:

  * [[evp_decrypt/6]]
  * [[evp_encrypt/6]]
