## Introduction {#crypto-introduction}

This library provides bindings  to  functionality   of  OpenSSL  that is
related to cryptography and authentication,   not  necessarily involving
connections, sockets or streams.

## Cryptographically secure random numbers {#crypto-random}

Almost  all  cryptographic  applications  require  the  availability  of
numbers that are sufficiently  unpredictable.  Examples are the creation
of  keys,  nonces  and  salts.   With this  library,  you  can  generate
cryptographically strong pseudo-random numbers for such use cases:

  * [[crypto_n_random_bytes/2]]

## Hashes {#crypto-hash}

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

### Hashes of data and files {#crypto-hash-basic}

The most important predicates to compute hashes are:

  * [[crypto_data_hash/3]]
  * [[crypto_file_hash/3]]

### Hashes of passwords {#crypto-hash-password}

For  the  important  case  of  deriving  hashes  from  _passwords_,  the
following specialised predicates are provided:

  * [[crypto_password_hash/2]]
  * [[crypto_password_hash/3]]

### Hashing incrementally {#crypto-hash-incremental}

The   following   predicates   are    provided   for   building   hashes
_incrementally_.   This  works  by  first creating  a  **context**  with
crypto_context_new/2, then using this context with crypto_data_context/3
to  incrementally  obtain  further  contexts, and  finally  extract  the
resulting hash with crypto_context_hash/2.

  * [[crypto_context_new/2]]
  * [[crypto_data_context/3]]
  * [[crypto_context_hash/2]]

The following hashing predicates work over _streams_:

  * [[crypto_open_hash_stream/3]]
  * [[crypto_stream_hash/2]]

## Representing binary data {#crypto-binary-data}

In the context of this library, _bytes_ can be represented as lists of
integers between 0 and 255. Such lists can be converted to and from
_hexadecimal notation_ with the following bidirectional relation:

  * [[hex_bytes/2]]

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
crypto_data_hash/3 and related predicates.

Signatures are also  represented in hexadecimal notation,  and you can
use hex_bytes/2 to convert them to and from lists of bytes (integers).

### ECDSA

  * [[ecdsa_sign/4]]
  * [[ecdsa_verify/4]]

### RSA

  * [[rsa_sign/4]]
  * [[rsa_verify/4]]

## Asymmetric encryption and decryption {#crypto-asymmetric}

The  following  predicates  provide   _asymmetric_  RSA  encryption  and
decryption.  This  means that the key  that is used for  _encryption_ is
different from the one used to _decrypt_ the data:

  * [[rsa_private_decrypt/4]]

## Symmetric encryption and decryption {#crypto-symmetric}

The following predicates provide _symmetric_ encryption and decryption:

  * [[evp_decrypt/6]]
  * [[evp_encrypt/6]]

## Number theory {#crypto-numbertheory}

This  library provides  operations  from number  theory that  frequently
arise   in  cryptographic   applications,  complementing   the  existing
built-ins and GMP bindings:

   * [[crypto_modular_inverse/3]]
   * [[crypto_generate_prime/3]]
   * [[crypto_is_prime/2]]

## Elliptic curves {#crypto-ec}

This  library  provides  functionality   for  reasoning  over  _elliptic
curves_. Elliptic curves are represented as opaque objects.  You acquire
a handle for an elliptic curve via crypto_name_curve/2.

A _point_ on a curve is  represented by the Prolog term =|point(X, Y)|=,
where  `X`  and `Y`  are  integers  that  represent the  point's  affine
coordinates.

The  following  predicates  are  provided for  reasoning  over  elliptic
curves:

    * [[crypto_name_curve/2]]
    * [[crypto_curve_order/2]]
    * [[crypto_curve_generator/2]]
    * [[crypto_curve_scalar_mult/4]]

## Example: Establishing a shared secret {#crypto-shared-secret}

As one example that involves most predicates of this library, we explain
a way to establish a _shared  secret_ over an insecure channel. We shall
use _elliptic curves_ for this purpose.

Suppose Alice  wants to establish  an encrypted connection with  Bob. To
achieve this  even over a channel  that may be subject  to eavesdrooping
and man-in-the-middle attacks, Bob performs the following steps:

    1. Choose an elliptic curve `C`, using crypto_name_curve/2.
    2. Pick a random integer _k_ such that _k_ is greater than 0 and
       smaller than the order of `C`. This can be done using
       crypto_curve_order/2 and crypto_n_random_bytes/2.
    3. Use crypto_curve_generator/2 to obtain the generator `G` of `C`, and
       use crypto_curve_scalar_mult/4 to compute the scalar product _k*G_.
       We call this result `R`, denoting a point on the curve.
    4. Sign `R` (using for example rsa_sign/4 or ecdsa_sign/4) and
       send this to Alice.

This mechanism hinges on a way for Alice to establish the _authenticity_
of  the   signed  message   (using  predicates  like   rsa_verify/4  and
ecdsa_verify/4),  for  example  by  means  of  a  public  key  that  was
previously exchanged or is signed by a  trusted party in such a way that
Alice can be sufficiently certain that it belongs to Bob.  However, none
of these steps require any encryption!

Alice in turn performs the following steps:

    1. Create a random integer _j_ such that _j_ is greater than 0 and
       smaller than the order of C. Alice can also use
       crypto_curve_order/2 and crypto_n_random_bytes/2 for this.
    2. Compute the scalar product _j*G_, where `G` is again the generator
       of `C` as obtained via crypto_curve_generator/2.
    3. Further, compute the scalar product _j*R_, which is a point on
       the curve that we shall call Q. We can derive a _shared secret_
       from `Q`, using for example crypto_data_hash/3, and encrypt any
       message with it (using for example evp_encrypt/6).
    4. Send the point _j*G_ and the encrypted message to Bob.

Bob  receives _j*G_  in plain  text and  can arrive  at the  same shared
secret  by  performing   the  calculation  _k*(j*G)_,  which   is  -  by
associativity and commutativity of  scalar multiplication - identical to
the point _j*(k*G)_,  which is again Q from which  the shared secret can
be derived, and the message can be decrypted with evp_decrypt/6.

This method is known as Diffie-Hellman-Merkle key exchange over elliptic
curves, abbreviated as  ECDH. It provides forward secrecy  (FS): Even if
the private key that was used  to establish the _authenticity_ of Bob is
later compromised, the encrypted messages cannot be decrypted with it.

A major attraction of using elliptic curves for this purpose is found in
the  comparatively small  key size  that  suffices to  make any  attacks
unrealistic as far as we currently know.  In particular, given any point
on the curve,  we currently have no efficient way  to determine by which
scalar the  generator was multiplied  to obtain that point.   The method
described above relies on the hardness of this so-called _elliptic curve
discrete logarithm  problem_ (ECDLP).   On the other  hand, some  of the
named curves have  been suspected to be  chosen in such a  way that they
could be prone to attacks that are not publicly known.

As an  alternative to  ECDH, you  can use the  original DH  key exchange
scheme,  where the  prime field  GF(p) is  used instead  of an  elliptic
curve, and _exponentiation_  of a suitable generator is  used instead of
scalar multiplication.  You can  use crypto_generate_prime/3 to generate
a sufficiently large prime for this purpose.
