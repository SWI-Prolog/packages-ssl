/*  Part of SWI-Prolog

    Author:        Jan Wielemaker
    E-mail:        J.Wielemaker@vu.nl
    WWW:           http://www.swi-prolog.org
    Copyright (C): 1985-2015, University of Amsterdam
			      VU University Amsterdam

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    As a special exception, if you link this library with other files,
    compiled with a Free Software compiler, to produce an executable, this
    library does not by itself cause the resulting executable to be covered
    by the GNU General Public License. This exception does not however
    invalidate any other reasons why the executable file might be covered by
    the GNU General Public License.
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

:- use_module(library(plunit)).
:- use_module(library(ssl)).
:- use_module(library(debug)).
:- use_module(library(error)).
:- use_module(library(readutil)).
:- use_module(library(socket)).
:- use_module(https).

%:- debug(connection).
%:- debug(certificate).
%:- debug(data).
%:- debug(_).

test_ssl :-
	run_tests([ ssl_server,
		    ssl_keys,
		    https_open,
                    ssl_certificates
		  ]).
:- dynamic
	option/1,			% Options to test
	copy_error/1.

run_network_tests :-
	\+ getenv('USE_PUBLIC_NETWORK_TESTS', false).

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

%%	skip_to_pem_cert(+Stream) is det.
%
%	Skip to "\n-", the beginning of   the PEM representation that is
%	embedded in certificates as produced using `CA.pl`.  If there is
%	no "\n-", real to the end of the file.

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
	memberchk(key(PublicKey), Cert),
	rsa_private_encrypt(PrivateKey, In, Encrypted),
	rsa_public_decrypt(PublicKey, Encrypted, Out).
test(trip_private_public, In == Out) :-
	numlist(1040, 1060, L),
	string_codes(In, L),
	from_file('tests/test_certs/server-key.pem', S1,
		  load_private_key(S1, "apenoot1", PrivateKey)),
	from_file('tests/test_certs/server-cert.pem', S2,
		  ( skip_to_pem_cert(S2),
		    load_certificate(S2, Cert)
		  )),
	memberchk(key(PublicKey), Cert),
	rsa_private_encrypt(PrivateKey, In, Encrypted),
	rsa_public_decrypt(PublicKey, Encrypted, Out).
test(trip_public_private, In == Out) :-
	In = "Hello World!",
	from_file('tests/test_certs/server-key.pem', S1,
		  load_private_key(S1, "apenoot1", PrivateKey)),
	from_file('tests/test_certs/server-cert.pem', S2,
		  ( skip_to_pem_cert(S2),
		    load_certificate(S2, Cert)
		  )),
	memberchk(key(PublicKey), Cert),
	rsa_public_encrypt(PublicKey, In, Encrypted),
	rsa_private_decrypt(PrivateKey, Encrypted, Out).

:- end_tests(ssl_keys).

:- begin_tests(ssl_server).

test(server) :-
	make_server(SSL),
	thread_create(server_loop(SSL), Id, []),
	(   catch(client, E, true)
	->  (   var(E)
	    ->	thread_join(Id, Status),
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
	make_server(SSL),
        server_loop(SSL).

		 /*******************************
		 *	       SERVER		*
		 *******************************/

:- dynamic
	stop_server/0.

make_server(SSL) :-
	ssl_init(SSL, server,
		 [ host('localhost'),
                   port(1111),
                   cert(true),
                   peer_cert(true),
		   cacert_file('tests/test_certs/rootCA/cacert.pem'),
		   certificate_file('tests/test_certs/server-cert.pem'),
		   key_file('tests/test_certs/server-key.pem'),
		   cert_verify_hook(get_cert_verify),
%		   password('apenoot1'),
		   pem_password_hook(get_server_pwd)
		 ]).

server_loop(SSL) :-
	ssl_accept(SSL, Socket, Peer),
	debug(connection, 'Connection from ~p', [Peer]),
	ssl_open(SSL, Socket, In, Out),
	(   option(timeout(T))
	->  set_stream(In, timeout(T))
	;   true
	),
	catch(copy_client(In, Out), E,
	      assert(copy_error(E))),
	close(In),
	close(Out),
	(   retract(stop_server)
	->  ssl_exit(SSL)
	;   server_loop(SSL)
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
	    (	atom_codes(bye, Line)
	    ->	assert(stop_server)
	    ;	true
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
		 *	       CLIENT		*
		 *******************************/

client :-
	ssl_init(SSL, client,
		 [ host('localhost'),
                   port(1111),
		   cert(true),
		   peer_cert(true),
		   cacert_file('tests/test_certs/rootCA/cacert.pem'),
		   certificate_file('tests/test_certs/client-cert.pem'),
		   key_file('tests/test_certs/client-key.pem'),
%		   password('apenoot2'),
		   pem_password_hook(get_client_pwd)
		 ]),
	client_loop(SSL),
        ssl_exit(SSL).

client_loop(SSL) :-
	ssl_open(SSL, In, Out),
        set_stream(In, timeout(1)),
	Message = 'Hello world',
	write_server(Message, In, Out),
	(   option(timeout(T))
	->  Wait is T*2,
	    sleep(Wait)
	;   true
	),
	write_server(bye, In, Out),
	close(In),
	close(Out).

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
	    (	Reply == Message
	    ->	true
	    ;	format(user_error, 'CLIENT: ERROR: Sent ~q, Got ~q~n',
		       [Message, Reply])
	    )
	).

get_client_pwd(_SSL, "apenoot2") :-
	debug(passwd, 'Returning password from client passwd hook', []).

:- end_tests(ssl_server).

		 /*******************************
		 *	       CERTS		*
		 *******************************/

:- begin_tests(ssl_certificates).

:- dynamic
        certificate_verification_result/1,
        stop_server/1.


do_verification_test(Key, Goal, VerificationResults, Status) :-
        retractall(stop_server(_)),
        tcp_socket(ServerFd),
	tcp_setopt(ServerFd, reuseaddr),
        tcp_bind(ServerFd, 2443),
        tcp_listen(ServerFd, 5),
        ( setup_call_cleanup(thread_create(verification_server(Key, ServerFd, Id), Id, []),
                             catch(Goal,
                                   Exception,
                                   Status = error(Exception)),
                             stop_verification_server(Id))->
            ignore(Status = true)
        ; Status = fail
        ),
        findall(VerificationResult,
                retract(certificate_verification_result(VerificationResult)),
                VerificationResults).

stop_verification_server(Id):-
        assert(stop_server(Id)),
        tcp_socket(S),
        catch((tcp_connect(S, localhost:2443, Read, Write),
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
        setup_call_cleanup(ssl_context(server,
                                       SSL,
                                       [ certificate_file(Cert),
                                         key_file(Key),
                                         password("apenoot")
                                       ]),
                           verification_server_loop(Id, ServerFd, SSL),
                           ssl_exit(SSL)).

verification_server_loop(Id, _ServerFd, _SSL) :-
        retract(stop_server(Id)), !.

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
        close(SSLOut),
        close(SSLIn).

try_ssl_client(Hostname, Port, Hook):-
        setup_call_cleanup(ssl_context(client,
                                       SSL,
                                       [ host(Hostname),
                                         port(Port),
                                         cert_verify_hook(Hook),
                                         cacert_file('tests/test_certs/rootCA/cacert.pem')
                                       ]),
                           % Always connect to localhost
                           verify_client(localhost:Port, SSL),
                           ssl_exit(SSL)).

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

test('Valid certificate, correct hostname in CN, signed by trusted CA', VerificationResults:Status == [verified, verified]:true):-
        do_verification_test(1, try_ssl_client('www.example.com', 2443, test_verify_hook), VerificationResults, Status).

test('Valid certificate, correct hostname in SAN, signed by trusted CA', VerificationResults:Status == [verified, verified]:true):-
        do_verification_test(2, try_ssl_client('www.example.com', 2443, test_verify_hook), VerificationResults, Status).

test('Valid certificate, incorrect hostname in CN, signed by trusted CA', VerificationResults:Status == [hostname_mismatch, verified, verified]:true):-
        do_verification_test(3, try_ssl_client('www.example.com', 2443, test_verify_hook), VerificationResults, Status).

test('Valid certificate, incorrect hostname in SAN and CN, signed by trusted CA', VerificationResults:Status == [hostname_mismatch, verified, verified]:true):-
        do_verification_test(4, try_ssl_client('www.example.com', 2443, test_verify_hook), VerificationResults, Status).

test('Valid certificate, correct wildcard hostname in SAN, signed by trusted CA', VerificationResults:Status == [verified, verified]:true):-
        do_verification_test(5, try_ssl_client('www.example.com', 2443, test_verify_hook), VerificationResults, Status).

test('Valid certificate, incorrect wildcard hostname in SAN, signed by trusted CA', VerificationResults:Status == [hostname_mismatch, verified, verified]:true):-
        do_verification_test(6, try_ssl_client('www.example.com', 2443, test_verify_hook), VerificationResults, Status).

test('Valid certificate, wildcard hostname in SAN with wildcard too high, signed by trusted CA', VerificationResults:Status == [hostname_mismatch, verified, verified]:true):-
        do_verification_test(7, try_ssl_client('www.example.com', 2443, test_verify_hook), VerificationResults, Status).

test('Valid certificate, wildcard hostname in SAN with wildcard too low, signed by trusted CA', VerificationResults:Status == [hostname_mismatch, verified, verified]:true):-
        do_verification_test(8, try_ssl_client('www.bad.example.com', 2443, test_verify_hook), VerificationResults, Status).

test('Valid certificate, wildcard hostname in SAN with wildcard in right level of domain, signed by trusted CA', VerificationResults:Status == [verified, verified]:true):-
        do_verification_test(9, try_ssl_client('www.good.example.com', 2443, test_verify_hook), VerificationResults, Status).

test('Valid certificate, illegal wildcard hostname in CN, signed by trusted CA', VerificationResults:Status == [hostname_mismatch, verified, verified]:true):-
        do_verification_test(10, try_ssl_client('www.good.example.com', 2443, test_verify_hook), VerificationResults, Status).

test('Hostname containing embedded NULL, signed by trusted CA',
     [ true(VerificationResults:Status ==
	    [hostname_mismatch,verified,verified]:true),
       condition((size_file('tests/test_certs/11-cert.pem', Size),
		  Size > 0))
     ]):-
        do_verification_test(11, try_ssl_client('www.example.com', 2443, test_verify_hook), VerificationResults, Status).

test('Certificate which has expired, signed by trusted CA', VerificationResults:Status == [verified, expired, verified]:true):-
        do_verification_test(12, try_ssl_client('www.example.com', 2443, test_verify_hook), VerificationResults, Status).

test('Certificate which is not yet valid, signed by trusted CA', VerificationResults:Status == [verified, not_yet_valid, verified]:true):-
        do_verification_test(13, try_ssl_client('www.example.com', 2443, test_verify_hook), VerificationResults, Status).

test('Certificate is not issued by trusted CA'):-
        do_verification_test(14, try_ssl_client('www.example.com', 2443, test_verify_hook), VerificationResults, Status),
        ( VerificationResults:Status == [unknown_issuer, unknown_issuer]:true ->
            % OpenSSL 1.0.2 and above
            true
        ; VerificationResults:Status == [unknown_issuer, not_trusted, unknown_issuer]:true ->
            % OpenSSL 1.0.1 and below
            true
        ).

test('Certificate is issued by trusted CA but has been altered so signature is wrong', VerificationResults:Status == [verified, bad_signature, verified]:true):-
        do_verification_test(15, try_ssl_client('www.example.com', 2443, test_verify_hook), VerificationResults, Status).

%test('Certificate has been revoked', VerificationResults:Status == [verified, verified]:true):-
%        do_verification_test(16, try_ssl_client('www.example.com', 2443, test_verify_hook), VerificationResults, Status).

test('Certificate is not intended for SSL', VerificationResults:Status == [bad_certificate_use, verified, verified]:true):-
        do_verification_test(17, try_ssl_client('www.example.com', 2443, test_verify_hook), VerificationResults, Status).

test('Certificate signed not-explicitly-trusted intermediary requiring us to follow the chain', VerificationResults:Status == [verified, verified, verified]:true):-
        do_verification_test(18, try_ssl_client('www.example.com', 2443, test_verify_hook), VerificationResults, Status).

%test('Chain involving revoked intermediary', VerificationResults:Status == [verified, verified]:true):-
%        do_verification_test(19, try_ssl_client('www.example.com', 2443, test_verify_hook), VerificationResults, Status).

test('Chain involving expired intermediary', VerificationResults:Status == [verified, expired, verified, verified]:true):-
        do_verification_test(20, try_ssl_client('www.example.com', 2443, test_verify_hook), VerificationResults, Status).

test('Chain involving not-yet-valid intermediary', VerificationResults:Status == [verified, not_yet_valid, verified, verified]:true):-
        do_verification_test(21, try_ssl_client('www.example.com', 2443, test_verify_hook), VerificationResults, Status).

test('Chain involving intermediary not authorized to sign certificates', VerificationResults:Status == [invalid_ca, bad_certificate_use, verified, verified, verified]:true):-
        do_verification_test(22, try_ssl_client('www.example.com', 2443, test_verify_hook), VerificationResults, Status).

test('Confirm that a failure in the verification callback triggers a connection abort', Status = error(_)):-
        do_verification_test(17, try_ssl_client('www.example.com', 2443, fail_verify_hook), _, Status).

test('Confirm that an exception in the verification callback triggers a connection abort', Status = error(_)):-
        do_verification_test(17, try_ssl_client('www.example.com', 2443, abort_verify_hook), _, Status).

:- end_tests(ssl_certificates).


		 /*******************************
		 *	       UTIL		*
		 *******************************/

is_certificate(Cert) :-
	is_list(Cert),
	memberchk(version(V), Cert), integer(V),
	memberchk(notbefore(NB), Cert), integer(NB),
	memberchk(notafter(NA), Cert), integer(NA),
	memberchk(subject(Subj), Cert), is_subject(Subj),
	memberchk(hash(H), Cert), is_hex_string(H),
	memberchk(signature(S), Cert), is_hex_string(S),
	memberchk(issuer_name(Issuer), Cert), is_issuer(Issuer),
	memberchk(key(K), Cert), is_public_key(K).

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
	functor(RSA, rsa, 8), !,
	RSA =.. [_|Args],
	maplist(is_bignum, Args).
is_key(ec_key).
is_key(dh_key).
is_key(dsa_key).

is_bignum('-').					% NULL
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


