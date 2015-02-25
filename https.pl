/*  Part of SWI-Prolog

    Author:        Jan Wielemaker
    E-mail:        J.Wielemaker@vu.nl
    WWW:           http://www.swi-prolog.org

    This demo code is released in the _public domain_, which implies
    you may copy, modify and reuse this code without restriction.
*/

:- module(https_server,
	  [ server/0,
	    server/2				% +Port, +Options
	  ]).
:- use_module('../http/demo_body').
:- use_module(library('http/thread_httpd')).
:- use_module(library('http/http_ssl_plugin')).

/** <module> Demo HTTPS server

This demo illustrates hot to  setup  a   minimal  HTTPS  server  using a
self-signed certificate.
*/

%%	server is det.
%%	server(?Port, +Options) is det.
%
%	Start HTTPS demo server.  The predicate server/0 starts the
%	server without options at port 1443.

server :-
	server(1443, []).

server(Port, Options) :-
	http_server(reply,
		    [ port(Port),
		      ssl([ certificate_file('etc/server/server-cert.pem'),
			    key_file('etc/server/server-key.pem'),
			    password('apenoot1')/*,
			    peer_cert(true),
			    cacert_file('etc/demoCA/cacert.pem'),
			    cert_verify_hook(get_cert_verify)*/
			  ])
		    | Options
		    ]).

:- public
	get_cert_verify/3.

get_cert_verify(_SSL, Certificate, Error) :-
	format('Handling client certificate verification~n'),
	format('Certificate: ~p, error: ~w~n', [Certificate, Error]),
	format('Server accepts the client certificate~n').
