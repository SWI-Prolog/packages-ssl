/*  Part of SWI-Prolog

    Author:        Jan Wielemaker
    E-mail:        J.Wielemaker@vu.nl
    WWW:           http://www.swi-prolog.org
    Copyright (c)  2013-2018, University of Amsterdam
                              VU University Amsterdam
                              CWI, Amsterdam
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

:- module(test_ssl,
          [ test_ssl/0
          ]).

:- asserta(user:file_search_path(library, '.')).
:- asserta(user:file_search_path(library, '../clib')).
:- asserta(user:file_search_path(library, '..')).
:- asserta(user:file_search_path(library, '../plunit')).
:- asserta(user:file_search_path(library, '../sgml')).
:- asserta(user:file_search_path(foreign, '../clib')).
:- asserta(user:file_search_path(foreign, '.')).
:- asserta(user:file_search_path(foreign, '../http')).
:- asserta(user:file_search_path(foreign, '../sgml')).
:- prolog_load_context(directory, D),
   asserta(user:file_search_path(library, D)).

:- use_module(library(plunit)).
:- use_module(library(ssl)).
:- use_module(library(crypto)).
:- use_module(library(debug)).
:- use_module(library(error)).
:- use_module(library(readutil)).
:- use_module(library(socket)).
:- use_module(library(https)).

%:- debug(connection).
%:- debug(certificate).
%:- debug(data).
%:- debug(_).

test_ssl :-
    run_tests([ ssl_options,
                ssl_server,
                ssl_keys,
                https_open,
                ssl_certificates,
                crypto_data_encrypt
              ]).
:- dynamic
    option/1,                       % Options to test
    copy_error/1.

run_network_tests :-
    \+ getenv('USE_PUBLIC_NETWORK_TESTS', false).

%!  cert_file(+File, -Absolute)
%
%   Find an absolute path to the certificates in the `etc` directory.

cert_file(File, Abs) :-
    source_file(test_ssl, MyFile),
    file_directory_name(MyFile, MyDir),
    atomic_list_concat([MyDir, File], /, Abs).

:- begin_tests(https_open, [condition(run_network_tests)]).

test(readme, Title == "# SWI-Prolog SSL interface") :-
    http_download('https://raw.githubusercontent.com\c
                      /SWI-Prolog/packages-ssl/master/README.md',
                  String),
    split_string(String, "\n", " \t", [Title|_]).

:- end_tests(https_open).

:- begin_tests(ssl_keys).

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
The tests in this  section  illustrate   SSL  encryption  as  public key
encryption. We use the server's private key and the server's certificate
public key for encryption and decryption of messages.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

:- meta_predicate
    from_file(+, ?, 0).

from_file(File, Stream, Goal) :-
    setup_call_cleanup(
        open(File, read, Stream, [type(binary)]),
        Goal,
        close(Stream)).

%!  skip_to_pem_cert(+Stream) is det.
%
%   Skip to "\n-", the beginning of   the PEM representation that is
%   embedded in certificates as produced using `CA.pl`.  If there is
%   no "\n-", real to the end of the file.

skip_to_pem_cert(In) :-
    repeat,
    (   peek_char(In, '-')
    ->  !
    ;   skip(In, 0'\n),  %'
        at_end_of_stream(In), !
    ).

test(private_key) :-
    from_file('tests/test_certs/server-key.pem', In,
              load_private_key(In, "apenoot1", Key)),
    is_private_key(Key).
test(certificate, true) :-
    from_file('tests/test_certs/server-cert.pem', In,
              ( skip_to_pem_cert(In),
                load_certificate(In, Cert)
              )),
    assertion(is_certificate(Cert)).
test(trip_private_public, In == Out) :-
    In = "Hello World!",
    from_file('tests/test_certs/server-key.pem', S1,
              load_private_key(S1, "apenoot1", PrivateKey)),
    from_file('tests/test_certs/server-cert.pem', S2,
              ( skip_to_pem_cert(S2),
                load_certificate(S2, Cert)
              )),
    certificate_field(Cert, public_key(PublicKey)),
    rsa_private_encrypt(PrivateKey, In, Encrypted, []),
    rsa_public_decrypt(PublicKey, Encrypted, Out, []).
test(trip_private_public, In == Out) :-
    numlist(1040, 1060, L),
    string_codes(In, L),
    from_file('tests/test_certs/server-key.pem', S1,
              load_private_key(S1, "apenoot1", PrivateKey)),
    from_file('tests/test_certs/server-cert.pem', S2,
              ( skip_to_pem_cert(S2),
                load_certificate(S2, Cert)
              )),
    certificate_field(Cert, public_key(PublicKey)),
    rsa_private_encrypt(PrivateKey, In, Encrypted, []),
    rsa_public_decrypt(PublicKey, Encrypted, Out, []).
test(trip_public_private, In == Out) :-
    In = "Hello World!",
    from_file('tests/test_certs/server-key.pem', S1,
              load_private_key(S1, "apenoot1", PrivateKey)),
    from_file('tests/test_certs/server-cert.pem', S2,
              ( skip_to_pem_cert(S2),
                load_certificate(S2, Cert)
              )),
    certificate_field(Cert, public_key(PublicKey)),
    rsa_public_encrypt(PublicKey, In, Encrypted, []),
    rsa_private_decrypt(PrivateKey, Encrypted, Out, []).

:- end_tests(ssl_keys).

:- begin_tests(ssl_options).

options_errmsg(Options, Msg) :-
    catch(ssl_context(server, _SSL, Options), Exception, true),
    nonvar(Exception),
    (   Exception = error(ssl_error(_, _, _, Msg), _)
    ->  true
    ;   Exception = error(existence_error(_,_), _)
    ->  Msg = existence_error
    ;   false
    ).

sni(SSL, _, SSL).

test(cert_mismatch, Msg == 'key values mismatch') :-
    cert_file('etc/server/server-cert.pem', CertFile),
    cert_file('etc/client/client-key.pem', KeyFile),
    options_errmsg([certificate_file(CertFile),
                    key_file(KeyFile),
                    password(apenoot2)], Msg).
test(cert_mismatch, Msg == 'key values mismatch') :-
    cert_file('etc/server/server-key.pem', KeyFile),
    cert_file('etc/client/client-cert.pem', CertFile),
    read_file_to_string(KeyFile, Key, []),
    read_file_to_string(CertFile, Cert, []),
    options_errmsg([certificate_key_pairs([Cert-Key]),
                    password('apenoot1')], Msg).
test(cert_mismatch, Msg == 'key values mismatch') :-
    cert_file('etc/server/server-key.pem', KeyFile),
    cert_file('etc/client/client-cert.pem', CertFile),
    read_file_to_string(KeyFile, Key, []),
    read_file_to_string(CertFile, Cert, []),
    options_errmsg([certificate_key_pairs([Cert-Key]),
                    password('apenoot1'),
                    sni_hook(sni)], Msg).

% missing certificate (key specified, with and without sni)

test(missing_cert, Msg == 'no certificate assigned') :-
    cert_file('etc/server/server-key.pem', KeyFile),
    options_errmsg([key_file(KeyFile),
                    password(apenoot1)], Msg).
test(missing_cert, Msg == 'no certificate assigned') :-
    cert_file('etc/server/server-key.pem', KeyFile),
    options_errmsg([key_file(KeyFile),
                    password(apenoot1),
                    sni_hook(sni)], Msg).

% missing key (certificate specified, with and without sni)

test(missing_key, Msg == 'no private key assigned') :-
    cert_file('etc/server/server-cert.pem', CertFile),
    options_errmsg([certificate_file(CertFile)], Msg).
test(missing_key, Msg == 'no private key assigned') :-
    cert_file('etc/server/server-cert.pem', CertFile),
    options_errmsg([certificate_file(CertFile),
                    sni_hook(sni)], Msg).

:- end_tests(ssl_options).

:- begin_tests(ssl_server).

test(server) :-
    make_server(SSL, Socket),
    thread_create(server_loop(SSL, Socket), Id, []),
    (   catch(client, E, true)
    ->  (   var(E)
        ->  thread_join(Id, Status),
            report_join_status(Status)
        ;   format(user_error, 'Client error:~n', []),
            print_message(error, E),
            thread_join(Id, Status),
            report_join_status(Status),
            fail
        )
    ).

report_join_status(true).
report_join_status(false) :-
    print_message(error, goal_failed(server_loop(_))).
report_join_status(exception(Term)) :-
    print_message(error, Term).

test_ssl(N) :-
    (   between(1, N, _),
        test_ssl,
        put('.'), flush_output,
        fail
    ;   true
    ).

ssl_server :-
    make_server(SSL, Socket),
    server_loop(SSL, Socket).

                 /*******************************
                 *             SERVER           *
                 *******************************/

:- dynamic
    stop_server/0,
    server_port/1.

make_server(SSL, Socket) :-
    ssl_context(server, SSL,
                [ peer_cert(true),
                  cacerts([file('tests/test_certs/rootCA/cacert.pem')]),
                  certificate_file('tests/test_certs/server-cert.pem'),
                  key_file('tests/test_certs/server-key.pem'),
                  cert_verify_hook(get_cert_verify),
%                     password('apenoot1'),
                  pem_password_hook(get_server_pwd)
                ]),
%   Port = 1111,
    tcp_socket(Socket),
    tcp_setopt(Socket, reuseaddr),
    tcp_bind(Socket, localhost:Port),
    retractall(server_port(_)),
    asserta(server_port(Port)),
    tcp_listen(Socket, 5).

server_loop(SSL, Server) :-
    tcp_accept(Server, Socket, Peer),
    debug(connection, 'Connection from ~p', [Peer]),
    tcp_open_socket(Socket, Read, Write),
    ssl_negotiate(SSL, Read, Write, In, Out),
    (   option(timeout(T))
    ->  set_stream(In, timeout(T))
    ;   true
    ),
    catch(copy_client(In, Out), E,
          assert(copy_error(E))),
    call_cleanup(close(In), close(Out)),
    (   retract(stop_server)
    ->  tcp_close_socket(Server)
    ;   server_loop(SSL, Server)
    ).

copy_client(In, Out) :-
    read_line_to_codes(In, Line),
    (   Line == end_of_file
    ->  true
    ;   debug(data, 'SERVER: Got ~s~n', [Line]),
        sleep(1.5),
        debug(data, 'SERVER: writing ~s~n', [Line]),
        format(Out, '~s~n', [Line]),
        flush_output(Out),
        (   atom_codes(bye, Line)
        ->  assert(stop_server)
        ;   true
        ),
        copy_client(In, Out)
    ).

get_server_pwd(_SSL, "apenoot1") :-
    debug(passwd, 'Returning password from server passwd hook', []).

get_cert_verify(SSL,
                ProblemCertificate, AllCertificates, FirstCertificate,
                Error) :-
    debug(certificate,
          'Accept from ~p, \c
               ProblemCert: ~p, AllCerts: ~p, FirstCert: ~p, \c
               Error: ~p',
          [ SSL,
            ProblemCertificate, AllCertificates, FirstCertificate,
            Error
          ]),
    (   Error == verified
    ->  true
    ;   domain_error(verified, Error)
    ).


                 /*******************************
                 *             CLIENT           *
                 *******************************/

client :-
    ssl_context(client, SSL,
             [ host('localhost'),
               cacerts([file('tests/test_certs/rootCA/cacert.pem')]),
               certificate_file('tests/test_certs/client-cert.pem'),
               key_file('tests/test_certs/client-key.pem'),
               close_parent(true),
%                  password('apenoot2'),
               pem_password_hook(get_client_pwd)
             ]),
    client_loop(SSL).

client_loop(SSL) :-
    server_port(Port),
    tcp_connect(localhost:Port, StreamPair, []),
    stream_pair(StreamPair, Read, Write),
    ssl_negotiate(SSL, Read, Write, In, Out),
    set_stream(In, timeout(1)),
    Message = 'Hello world',
    write_server(Message, In, Out),
    (   option(timeout(T))
    ->  Wait is T*2,
        sleep(Wait)
    ;   true
    ),
    write_server(bye, In, Out),
    call_cleanup(close(In), close(Out)).

write_server(Message, In, Out) :-
    debug(data, 'CLIENT: writing: ~q~n', [Message]),
    write(Out, Message), nl(Out),
    flush_output(Out),
    sleep(0.1),
    catch(read_from_server(In, Message),
          E,
          debug(data, 'CLIENT: exception: ~q~n', [E])),
    (   var(E)
    ->  true
    ;   read_from_server(In, Message)
    ).

read_from_server(In, Message) :-
    debug(data, 'CLIENT: attempting to read reply from stream~n', []),
    read_line_to_codes(In, Line),
    (   Line == end_of_file
    ->  true
    ;   atom_codes(Reply, Line),
        debug(data, 'CLIENT: Got ~q~n', [Reply]),
        (   Reply == Message
        ->  true
        ;   format(user_error, 'CLIENT: ERROR: Sent ~q, Got ~q~n',
                   [Message, Reply])
        )
    ).

get_client_pwd(_SSL, "apenoot2") :-
    debug(passwd, 'Returning password from client passwd hook', []).

:- end_tests(ssl_server).

                 /*******************************
                 *             CERTS            *
                 *******************************/

:- begin_tests(ssl_certificates).

:- dynamic
    certificate_verification_result/1,
    stop_server/1,
    test_port/1.

:- meta_predicate
    do_verification_test(+, 0, -, -).

do_verification_test(Key, Goal, VerificationResults, Status) :-
%   Port = 2443,
    retractall(stop_server(_)),
    tcp_socket(ServerFd),
    tcp_setopt(ServerFd, reuseaddr),
    tcp_bind(ServerFd, Port),
    tcp_listen(ServerFd, 5),
    retractall(test_port(_)),
    asserta(test_port(Port)),
    (   setup_call_cleanup(
            thread_create(verification_server(Key, ServerFd, Id), Id, []),
            catch(Goal,
                  Exception,
                  Status = error(Exception)),
            stop_verification_server(Id))
    ->  ignore(Status = true)
    ;   Status = fail
    ),
    findall(VerificationResult,
            retract(certificate_verification_result(VerificationResult)),
            VerificationResults).

stop_verification_server(Id):-
    assert(stop_server(Id)),
    tcp_socket(S),
    test_port(Port),
    catch((tcp_connect(S, localhost:Port, Read, Write),
           close(Write, [force(true)]),
           close(Read, [force(true)])),
          _,
          tcp_close_socket(S)),
    thread_join(Id, _Status).

verification_server(TestKey, ServerFd, Id):-
    setup_call_cleanup(true,
                       verification_server_1(TestKey, Id, ServerFd),
                       tcp_close_socket(ServerFd)).

verification_server_1(TestKey, Id, ServerFd):-
    tcp_listen(ServerFd, 5),
    format(atom(Key), 'tests/test_certs/~w-key.pem', [TestKey]),
    format(atom(Cert), 'tests/test_certs/~w-cert.pem', [TestKey]),
    ssl_context(server, SSL,
                [ certificate_file(Cert),
                  key_file(Key),
                  password("apenoot")
                ]),
    verification_server_loop(Id, ServerFd, SSL).

verification_server_loop(Id, _ServerFd, _SSL) :-
    retract(stop_server(Id)),
    !.

verification_server_loop(Id, ServerFd, SSL) :-
    catch(accept_client(ServerFd, SSL),
          _Term,
          true),
    verification_server_loop(Id, ServerFd, SSL).

accept_client(ServerFd, SSL):-
    tcp_accept(ServerFd, ClientFd, _Peer),
    setup_call_cleanup(tcp_open_socket(ClientFd, PlainIn, PlainOut),
                       dispatch_client(SSL, PlainIn, PlainOut),
                       ( close(PlainOut, [force(true)]),
                         close(PlainIn, [force(true)])
                       )).


dispatch_client(SSL, PlainIn, PlainOut):-
    ssl_negotiate(SSL, PlainIn, PlainOut, SSLIn, SSLOut),
    set_stream(SSLIn, timeout(5)),
    read_line_to_codes(SSLIn, Codes),
    format(SSLOut, '~s~n', [Codes]),
    flush_output(SSLOut),
    call_cleanup(close(SSLOut), close(SSLIn)).

:- meta_predicate
    try_ssl_client(+, 5),
    try_ssl_client(+, 5, +).

try_ssl_client(Hostname, Hook):-
    try_ssl_client(Hostname, Hook, []).

try_ssl_client(Hostname, Hook, Options):-
    test_port(Port),
    ssl_context(client, SSL,
                [ host(Hostname),
                  port(Port),
                  cert_verify_hook(Hook),
                  cacerts([file('tests/test_certs/rootCA/cacert.pem')])
                | Options
                ]),
    % Always connect to localhost
    verify_client(localhost:Port, SSL).

verify_client(Address, SSL) :-
    tcp_socket(S),
    setup_call_cleanup(tcp_connect(S, Address, PlainIn, PlainOut),
                       verify_client_1(SSL, PlainIn, PlainOut),
                       ( close(PlainOut, [force(true)]),
                         close(PlainIn, [force(true)])
                       )).

verify_client_1(SSL, PlainIn, PlainOut):-
    set_stream(PlainIn, timeout(1)),
    setup_call_cleanup(ssl_negotiate(SSL, PlainIn, PlainOut, SSLIn, SSLOut),
                       ( format(SSLOut, 'Hello~n', []),
                         flush_output(SSLOut)
                       ),
                       ( close(SSLOut, [force(true)]),
                         close(SSLIn, [force(true)])
                       )).

zz(Goal):-
    setup_call_catcher_cleanup(format('CALL : ~q~n', [Goal]),
                               Goal,
                               Catcher,
                               ( Catcher = exception(E) -> format('ERROR: ~q (~q)~n', [Goal, E])
                               ; Catcher == fail-> format('FAIL : ~q~n', [Goal])
                               ; format('EXIT : ~q~n', [Goal]))
                              ),
    ( var(Catcher)->
        format('PEND : ~q~n', [Goal])
    ; true
    ).


test_verify_hook(_,_,_,_,Error):-
    assert(certificate_verification_result(Error)).

fail_verify_hook(_,_,_,_,Error):-
    Error == verified.

abort_verify_hook(_,_,_,_,Error):-
    ( Error == verified->
        true
    ; throw(error(certificate_error(Error), _))
    ).

test_crl_hook(_, _, _, _, verified).
test_crl_hook(_SSL, Cert, _Chain, _Tail, revoked):-
    setup_call_cleanup(open('tests/test_certs/rootCA-crl.pem', read, Stream),
                       load_crl(Stream, CRL),
                       close(Stream)),
    certificate_field(Cert, serial(Serial)),
    memberchk(revocations(Revocations), CRL),
    \+memberchk(revoked(Serial, _RevocationTime), Revocations).


test('Valid certificate, correct hostname in CN, signed by trusted CA', VerificationResults:Status == [verified, verified]:true):-
    do_verification_test(1, try_ssl_client('www.example.com', test_verify_hook), VerificationResults, Status).

test('Valid certificate, correct hostname in SAN, signed by trusted CA', VerificationResults:Status == [verified, verified]:true):-
    do_verification_test(2, try_ssl_client('www.example.com', test_verify_hook), VerificationResults, Status).

test('Valid certificate, incorrect hostname in CN, signed by trusted CA', VerificationResults:Status == [hostname_mismatch, verified, verified]:true):-
    do_verification_test(3, try_ssl_client('www.example.com', test_verify_hook), VerificationResults, Status).

test('Valid certificate, incorrect hostname in SAN and CN, signed by trusted CA', VerificationResults:Status == [hostname_mismatch, verified, verified]:true):-
    do_verification_test(4, try_ssl_client('www.example.com', test_verify_hook), VerificationResults, Status).

test('Valid certificate, correct wildcard hostname in SAN, signed by trusted CA', VerificationResults:Status == [verified, verified]:true):-
    do_verification_test(5, try_ssl_client('www.example.com', test_verify_hook), VerificationResults, Status).

test('Valid certificate, incorrect wildcard hostname in SAN, signed by trusted CA', VerificationResults:Status == [hostname_mismatch, verified, verified]:true):-
    do_verification_test(6, try_ssl_client('www.example.com', test_verify_hook), VerificationResults, Status).

test('Valid certificate, wildcard hostname in SAN with wildcard too high, signed by trusted CA', VerificationResults:Status == [hostname_mismatch, verified, verified]:true):-
    do_verification_test(7, try_ssl_client('www.example.com', test_verify_hook), VerificationResults, Status).

test('Valid certificate, wildcard hostname in SAN with wildcard too low, signed by trusted CA', VerificationResults:Status == [hostname_mismatch, verified, verified]:true):-
    do_verification_test(8, try_ssl_client('www.bad.example.com', test_verify_hook), VerificationResults, Status).

test('Valid certificate, wildcard hostname in SAN with wildcard in right level of domain, signed by trusted CA', VerificationResults:Status == [verified, verified]:true):-
    do_verification_test(9, try_ssl_client('www.good.example.com', test_verify_hook), VerificationResults, Status).

test('Valid certificate, illegal wildcard hostname in CN, signed by trusted CA', VerificationResults:Status == [hostname_mismatch, verified, verified]:true):-
    do_verification_test(10, try_ssl_client('www.good.example.com', test_verify_hook), VerificationResults, Status).

test('Hostname containing embedded NULL, signed by trusted CA',
     [ true(VerificationResults:Status ==
            [hostname_mismatch,verified,verified]:true),
       condition((size_file('tests/test_certs/11-cert.pem', Size),
                  Size > 0))
     ]):-
    do_verification_test(11, try_ssl_client('www.example.com', test_verify_hook), VerificationResults, Status).

test('Certificate which has expired, signed by trusted CA', VerificationResults:Status == [verified, expired, verified]:true):-
    do_verification_test(12, try_ssl_client('www.example.com', test_verify_hook), VerificationResults, Status).

test('Certificate which is not yet valid, signed by trusted CA', VerificationResults:Status == [verified, not_yet_valid, verified]:true):-
    do_verification_test(13, try_ssl_client('www.example.com', test_verify_hook), VerificationResults, Status).

test('Certificate is not issued by trusted CA'):-
    do_verification_test(14, try_ssl_client('www.example.com', test_verify_hook), VerificationResults, Status),
    ( VerificationResults:Status == [unknown_issuer, unknown_issuer]:true ->
        % OpenSSL 1.0.2 and above
        true
    ; VerificationResults:Status == [unknown_issuer, not_trusted, unknown_issuer]:true ->
        % OpenSSL 1.0.1 and below
        true
    ).

test('Certificate is issued by trusted CA but has been altered so signature is wrong', VerificationResults:Status == [verified, bad_signature, verified]:true):-
    do_verification_test(15, try_ssl_client('www.example.com', test_verify_hook), VerificationResults, Status).

test('Certificate is not intended for SSL', VerificationResults:Status == [bad_certificate_use, verified, verified]:true):-
    do_verification_test(17, try_ssl_client('www.example.com', test_verify_hook), VerificationResults, Status).

test('Certificate signed not-explicitly-trusted intermediary requiring us to follow the chain', VerificationResults:Status == [verified, verified, verified]:true):-
    do_verification_test(18, try_ssl_client('www.example.com', test_verify_hook), VerificationResults, Status).

test('Chain involving expired intermediary', VerificationResults:Status == [verified, expired, verified, verified]:true):-
    do_verification_test(20, try_ssl_client('www.example.com', test_verify_hook), VerificationResults, Status).

test('Chain involving not-yet-valid intermediary', VerificationResults:Status == [verified, not_yet_valid, verified, verified]:true):-
    do_verification_test(21, try_ssl_client('www.example.com', test_verify_hook), VerificationResults, Status).

test('Chain involving intermediary not authorized to sign certificates', VerificationResults:Status == [invalid_ca, bad_certificate_use, verified, verified, verified]:true):-
    do_verification_test(22, try_ssl_client('www.example.com', test_verify_hook), VerificationResults, Status).

test('Confirm that a failure in the verification callback triggers a connection abort', Status = error(_)):-
    do_verification_test(17, try_ssl_client('www.example.com', fail_verify_hook), _, Status).

test('Confirm that an exception in the verification callback triggers a connection abort', Status = error(_)):-
    do_verification_test(17, try_ssl_client('www.example.com', abort_verify_hook), _, Status).


test('Certificate has a CRL but has not been revoked. We do not provide the CRL', VerificationResults:Status == [unknown_crl, unknown_crl, verified, verified]:true):-
    do_verification_test(23, try_ssl_client('www.example.com', test_verify_hook, [require_crl(true)]), VerificationResults, Status).

test('Certificate has a CRL but has not been revoked. We do provide the CRL', VerificationResults:Status == [verified, verified]:true):-
    do_verification_test(23, try_ssl_client('www.example.com', test_verify_hook, [require_crl(true), crl(['tests/test_certs/rootCA-crl.pem'])]), VerificationResults, Status).

test('Certificate has a CRL and has been revoked. We do not provide the CRL', VerificationResults:Status == [unknown_crl, unknown_crl, verified, verified]:true):-
    do_verification_test(24, try_ssl_client('www.example.com', test_verify_hook, [require_crl(true)]), VerificationResults, Status).

test('Certificate has a CRL and has been revoked. We do provide the CRL', VerificationResults:Status == [revoked, verified, verified]:true):-
    do_verification_test(24, try_ssl_client('www.example.com', test_verify_hook, [require_crl(true), crl(['tests/test_certs/rootCA-crl.pem'])]), VerificationResults, Status).

test('Certificate has a CRL but we want to ignore it', VerificationResults:Status == [verified, verified]:true):-
    do_verification_test(24, try_ssl_client('www.example.com', test_verify_hook), VerificationResults, Status).

test('Certificate has an illegal CRL', VerificationResults:Status == [bad_certificate_use, verified, verified, verified]:true):-
    do_verification_test(25, try_ssl_client('www.example.com', test_verify_hook, [require_crl(true), crl(['tests/test_certs/25-crl.pem', 'tests/test_certs/rootCA-crl.pem'])]), VerificationResults, Status).

test('Intermediate CA has revoked the certificate', VerificationResults:Status == [revoked, verified, verified, verified]:true):-
    do_verification_test(26, try_ssl_client('www.example.com', test_verify_hook, [require_crl(true), crl(['tests/test_certs/26-crl.pem', 'tests/test_certs/rootCA-crl.pem'])]), VerificationResults, Status).

test('root CA has revoked the intermediate CA', VerificationResults:Status == [revoked, verified, verified, verified]:true):-
    do_verification_test(27, try_ssl_client('www.example.com', test_verify_hook, [require_crl(true), crl(['tests/test_certs/27-crl.pem', 'tests/test_certs/rootCA-crl.pem'])]), VerificationResults, Status).


test('Accept a non-revoked certificate ourselves in a callback', VerificationResults:Status == []:true):-
    do_verification_test(23, try_ssl_client('www.example.com', test_crl_hook, [require_crl(true), crl(['tests/test_certs/rootCA-crl.pem'])]), VerificationResults, Status).

test('Reject a revoked certificate ourselves in a callback', Status = error(_)):-
    do_verification_test(24, try_ssl_client('www.example.com', test_crl_hook, [require_crl(true), crl(['tests/test_certs/rootCA-crl.pem'])]), _, Status).

% It would be really nice if there were some way of adding the CRL to the context and retrying, but I dont think this is possible.
% Looking at the code in x509_vfy.c, once the callback is called for X509_V_ERR_UNABLE_TO_GET_CRL, regardless of the callback status, it goes to err, skipping the
% rest of the validation. This implies that the callback has necessarily handled not only obtaining the CRL, but also checking that the certificate in question is
% not revoked


:- end_tests(ssl_certificates).


:- begin_tests(crypto_data_encrypt).

test(roundtrip, RecoveredText == Text) :-
    Key  = "sixteenbyteofkey",
    IV   = "sixteenbytesofiv",
    Text = "this is some input",

    crypto_data_encrypt(Text, 'aes-128-cbc', Key, IV, CipherText, []),
    crypto_data_decrypt(CipherText, 'aes-128-cbc', Key, IV, RecoveredText, []).

:- end_tests(crypto_data_encrypt).


                 /*******************************
                 *             UTIL             *
                 *******************************/

is_certificate(Cert) :-
    blob(Cert, ssl_certificate),
    certificate_field(Cert, version(V)), integer(V),
    certificate_field(Cert, not_before(NB)), integer(NB),
    certificate_field(Cert, not_after(NA)), integer(NA),
    certificate_field(Cert, subject(Subj)), is_subject(Subj),
    certificate_field(Cert, hash(H)), is_hex_string(H),
    certificate_field(Cert, signature(S)), is_hex_string(S),
    certificate_field(Cert, issuer(Issuer)), is_issuer(Issuer),
    certificate_field(Cert, public_key(K)), is_public_key(K).

is_subject(Subj) :-
    is_list(Subj),
    memberchk('CN' = CN, Subj), atom(CN).

is_issuer(Issuer) :-
    is_list(Issuer),
    memberchk('CN' = CN, Issuer), atom(CN).

is_public_key(Term) :-
    nonvar(Term),
    Term = public_key(Key),
    is_key(Key).

is_private_key(Term) :-
    nonvar(Term),
    Term = private_key(Key),
    is_key(Key).

is_key(Term) :-
    var(Term), !, fail.
is_key(RSA) :-
    functor(RSA, rsa, 8),
    !,
    RSA =.. [_|Args],
    maplist(is_bignum, Args).
is_key(ec_key).
is_key(dh_key).
is_key(dsa_key).

is_bignum('-').                                 % NULL
is_bignum(Text) :-
    string_codes(Text, Codes),
    maplist(is_hex, Codes).

is_hex_string(S) :-
    string(S),
    string_codes(S, Codes),
    maplist(is_hex, Codes).


is_hex(C) :- between(0'0, 0'9, C), !.
is_hex(C) :- between(0'A, 0'F, C), !.
is_hex(C) :- between(0'a, 0'f, C), !.


