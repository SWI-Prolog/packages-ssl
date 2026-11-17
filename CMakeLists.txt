cmake_minimum_required(VERSION 3.10)
project(swipl-ssl)

include("../cmake/PrologPackage.cmake")
include(Sockets)

find_package(OpenSSL)
if(OPENSSL_FOUND)

if(NOT OPENSSL_OS_LIBS)
  if(WIN32)
    set(OPENSSL_OS_LIBS ws2_32.lib gdi32.lib crypt32.lib ${ZLIB_LIBRARIES})
  else()
    set(OPENSSL_OS_LIBS)
  endif()
endif()

set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES}
    ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_LIBRARIES} ${OPENSSL_OS_LIBS})
if(APPLE)
set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES}
    "-framework CoreFoundation" "-framework Security")
endif()
set(CMAKE_REQUIRED_INCLUDES  ${CMAKE_REQUIRED_INCLUDES}
    ${OPENSSL_INCLUDE_DIR})

AC_CHECK_HEADERS(Security/Security.h)

check_c_source_compiles(
    "#include <sys/types.h>
     #include <Security/Security.h>

     int main() { const void *key = kSecClass; return 0; }"
    HAVE_KSECCLASS)

include(CheckSymbolExists)
check_symbol_exists(ASN1_STRING_get0_data openssl/ssl.h
		    HAVE_ASN1_STRING_get0_data)
check_symbol_exists(ASN1_STRING_get_length openssl/ssl.h
		    HAVE_ASN1_STRING_get_length)

AC_CHECK_FUNCS(timegm)
AC_CHECK_FUNCS(X509_check_host)
AC_CHECK_FUNCS(i2d_re_X509_tbs)
AC_CHECK_FUNCS(EVP_blake2b512 EVP_blake2s256)
AC_CHECK_FUNCS(EVP_sha3_224 EVP_sha3_256 EVP_sha3_384 EVP_sha3_512)
AC_CHECK_FUNCS(HMAC_CTX_new HMAC_CTX_free)
AC_CHECK_FUNCS(EVP_PKEY_new EVP_PKEY_free EVP_PKEY_get_bn_param EVP_PKEY_get_octet_string_param EVP_PKEY_get_size EVP_PKEY_decrypt EVP_PKEY_encrypt EVP_PKEY_sign EVP_PKEY_verify)
AC_CHECK_FUNCS(EVP_PKEY_Q_keygen)
AC_CHECK_FUNCS(EVP_PKEY_new_raw_private_key EVP_PKEY_new_raw_public_key EVP_PKEY_get_raw_private_key EVP_PKEY_get_raw_public_key)
AC_CHECK_FUNCS(EVP_DigestSign EVP_DigestVerify)
AC_CHECK_FUNCS(OSSL_PARAM_construct_utf8_string)
AC_CHECK_FUNCS(BN_check_prime)
AC_CHECK_FUNCS(OSSL_PARAM_BLD_new)

AC_CHECK_HEADERS(openssl/kdf.h)
AC_CHECK_HEADERS(openssl/core_names.h)
AC_CHECK_HEADERS(openssl/param_build.h)
AC_CHECK_HEADERS(openssl/applink.c)
if(MSVC AND HAVE_OPENSSL_APPLINK_C)
  set(APPLINK ssl_applink.c)
else()
  set(APPLINK)
endif()


if(NOT DEFINED SYSTEM_CACERT_FILENAME)
  if(APPLE)
    # Do not probe: the probe runs on the build host, while the only
    # trusted certificate file on macOS is /etc/ssl/cert.pem.  If it is
    # not there we fall back to the keychain at runtime.
    set(SYSTEM_CACERT_FILENAME /etc/ssl/cert.pem)
  else()
    set(CERT_CANDIDATES
	/data/data/com.termux/files/usr/etc/tls/cert.pem
	/etc/ssl/certs/ca-certificates.crt
	/etc/pki/tls/certs/ca-bundle.crt
	/etc/ssl/ca-bundle.pem
	/etc/ssl/cert.pem)

    set(SYSTEM_CACERT_FILENAME /etc/ssl/certs/ca-certificates.crt)
    foreach(f ${CERT_CANDIDATES})
      if(EXISTS ${f})
	set(SYSTEM_CACERT_FILENAME ${f})
      endif()
    endforeach()
  endif()
  set(SYSTEM_CACERT_FILENAME ${SYSTEM_CACERT_FILENAME}
      CACHE STRING
      "Location of the system TLS root certificate file")
endif()

configure_file(config.h.cmake config.h)

if(BUILD_TESTING AND NOT SKIP_SSL_TESTS)
  if(NOT PROG_OPENSSL)
    set(prog_openssl_new ON)
  endif()

  if(CMAKE_CROSSCOMPILING AND SWIPL_NATIVE_FRIEND)
    find_program(PROG_OPENSSL openssl${CMAKE_HOST_EXECUTABLE_SUFFIX}
		 PATHS /usr/bin /bin /usr/sbin /sbin
		       /opt/local/bin /opt/local/sbin
		       /usr/local/bin /usr/local/sbin
		 NO_CMAKE_FIND_ROOT_PATH                   # Do not search cross compiling paths
		 NO_DEFAULT_PATH)
  else()
    find_program(PROG_OPENSSL openssl${CMAKE_EXECUTABLE_SUFFIX}
		 HINTS ${OPENSSL_ROOT_DIR}/bin)
  endif()

  if(PROG_OPENSSL)
    if(prog_openssl_new)
      message("-- Using ${PROG_OPENSSL} to create ssl test certificates")
    endif()
    configure_file(mkcerts.pl.in mkcerts.pl @ONLY)
    set(SSL_TESTS ON)
  else()
    message("-- Could not find openssl program.  Skipping ssl tests")
    set(SSL_TESTS OFF)
  endif()

  unset(prog_openssl_new)

  if(SSL_TESTS)
    add_custom_command(
	OUTPUT  tests/test_certs/generated
	COMMAND ${CMAKE_COMMAND} -E make_directory tests
	COMMAND ${PROG_SWIPL} -f none --no-packs
			      ${CMAKE_CURRENT_BINARY_DIR}/mkcerts.pl
		              --source=${CMAKE_CURRENT_SOURCE_DIR}/tests
		              --dest=tests
	COMMAND touch tests/test_certs/generated
	DEPENDS core prolog_home clib)
    add_custom_target(
	test_certificates ALL
	DEPENDS tests/test_certs/generated)

    test_libs(
	ssl
	PACKAGES clib sgml http
    )

    if(INSTALL_TESTS)
      install(FILES https.pl
	      DESTINATION ${INSTALL_TESTS_DIR}/packages/ssl
	      COMPONENT Tests)
      install(DIRECTORY etc
	      DESTINATION ${INSTALL_TESTS_DIR}/packages/ssl
	      COMPONENT Tests)
      install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/tests
	      DESTINATION ${INSTALL_TESTS_DIR}/packages/ssl
	      COMPONENT Tests)
    endif()
  endif()
endif(BUILD_TESTING AND NOT SKIP_SSL_TESTS)

has_package(http HAVE_HTTP)

add_compile_options(-D__SWI_PROLOG__
		    -DSERVER_CERT_REQUIRED=TRUE
		    -DCLIENT_CERT_REQUIRED=TRUE)

swipl_plugin(
    ssl4pl
    C_SOURCES ssl4pl.c ${APPLINK} ../clib/error.c
    THREADED
    C_LIBS ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_OS_LIBS}
    C_INCLUDE_DIR ${OPENSSL_INCLUDE_DIR}
    PL_LIBS ssl.pl)
swipl_plugin(
    crypto4pl
    C_SOURCES crypto4pl.c crypt_blowfish.c ../clib/error.c
    THREADED
    C_LIBS ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_OS_LIBS}
    C_INCLUDE_DIR ${OPENSSL_INCLUDE_DIR}
    PL_LIBS crypto.pl)
if(APPLE)
target_link_libraries(
    plugin_ssl4pl PRIVATE
    "-framework CoreFoundation"
    "-framework Security")
endif()

install_dll(${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})

swipl_plugin(
    saml
    PL_LIBS saml.pl xmldsig.pl xmlenc.pl)

add_custom_target(ssl)
add_dependencies(
    ssl
    ssl4pl crypto4pl saml)

if(HAVE_HTTP)
  swipl_plugin(
      ssl_http_plugin
      PL_LIB_SUBDIR http
      PL_LIBS http_ssl_plugin.pl)
  add_dependencies(ssl ssl_http_plugin)
endif()

swipl_examples(client.pl server.pl https.pl)

install_src(pkg_ssl_etc
	    DIRECTORY etc
	    DESTINATION
	    ${SWIPL_INSTALL_SHARE_PREFIX}/doc/packages/examples/${SWIPL_PKG}
	    COMPONENT Examples)

pkg_doc(ssl
	SOURCES
	    crypto.plx
	SECTION
	    SOURCE ssl.pl ssllib.tex
	    SOURCE cryptolib.md --lib=crypto --module=crypto
	SUBSECTION
	    saml.pl xmldsig.pl xmlenc.pl
        DEPENDS ssl zlib)

endif(OPENSSL_FOUND)
