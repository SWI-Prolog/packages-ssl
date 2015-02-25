/*  Part of SWI-Prolog

    Author:        Jan Wielemaker
    E-mail:        J.Wielemaker@vu.nl
    WWW:           http://www.swi-prolog.org

    This demo code is released in the _public domain_, which implies
    you may copy, modify and reuse this code without restriction.
*/

:- module(https_server,
	  [ server/1,				% ?Port
	    server_with_client_cert/1		% ?Port
	  ]).
:- if(exists_source('../http/examples/demo_body')).
:- use_module('../http/examples/demo_body').	% location in source tree
:- else.
:- use_module('../http/demo_body').		% location in demo tree
:- endif.
:- use_module(library('http/thread_httpd')).
:- use_module(library('http/http_ssl_plugin')).

/** <module> Demo HTTPS server

This demo illustrates how to setup   an HTTPS server using (self-signed)
certificates. The certificates are  provided   in  the  `etc` directory.
These certificates are the same certificates   that are used for testing
the SSL library. You may use them   for testing purposes, but you should
not use them for your own services  because   the  private key is not so
private.

This demo gives two versions:

  - server/1 implements a typical HTTPS server.
  - server_with_client_cert/1 implements a server that asks

The startup sequence to run the  server   at  port  1443 is shown below.
Directing your browser to the indicated URL should cause your browser to
warn you about an untrusted certificate. After accepting you can use the
simple demo through HTTPS.

  ==
  $ swipl https.pl
  ...
  ?- server(1443).
  % Started server at https://localhost:1443/
  true.
  ==

*/

%%	server(?Port) is det.
%
%	Start an HTTPS demo server at Port.   Compared  to a normal HTTP
%	server, this requires two additional SSL components:
%
%	  1. The server certificate.  This is basically a public
%	  key, so there is no need to keep this secret.
%	  2. The server private key.  If someone manages to grab
%	  this key, he can setup a server that claims to be you.
%	  There are two ways to protect it.  One is to make sure
%	  the file cannot be obtained and the other is to protect
%	  it using a password and make sure that the password is
%	  kept secret.  Our server uses a password, but it is not
%	  very secret.  See also the `pem_password_hook` option
%	  of ssl_context/3.
%
%	Note that anyone can access this  server. You can implement HTTP
%	authentication or cookie based password login in the application
%	to realise a safe login procedure  where attackers cannot easily
%	steal the HTTP authentication token or cookie.

server(Port) :-
	http_server(reply,
		    [ port(Port),
		      ssl([ certificate_file('etc/server/server-cert.pem'),
			    key_file('etc/server/server-key.pem'),
			    password('apenoot1')
			  ])
		    ]).


%%	server_with_client_cert/1
%
%	Our second server  is  a  setup   that  is  typically  used  for
%	administrative tasks where users  are   handed  a certificate to
%	login. In our example, we use the client certificate and private
%	key that can be found in etc/client.   First  of all, we need to
%	combine these into a `.p12` (PKCS12)   file.  This is done using
%	`openssl`  as  below.  We  provide  the    .p12  file  for  your
%	convenience.
%
%	  ==
%	  $ openssl pkcs12 -export \
%		-inkey client-key.pem -in client-cert.pem \
%		-name jan -out client-cert.p12
%	  Enter pass phrase for client-key.pem: apenoot2
%	  Enter Export Password: secret
%	  ==
%
%	Next, import `client-cert.p12` into your   browser. For firefox,
%	this is in   Edit/Preference/Advanced/View  Certificates/Import.
%	When requested for the password, enter "secret".

server_with_client_cert(Port) :-
	http_server(reply,
		    [ port(Port),
		      ssl([ certificate_file('etc/server/server-cert.pem'),
			    key_file('etc/server/server-key.pem'),
			    password('apenoot1'),
			    peer_cert(true),
			    cacert_file('etc/demoCA/cacert.pem'),
			    cert_verify_hook(client_cert_verify)
			  ])
		    ]).

:- public
	client_cert_verify/5.

client_cert_verify(_SSL, _Problem, _AllCerts, First, Error) :-
	format('Handling client certificate verification~n'),
	format('Certificate: ~p, error: ~w~n', [First, Error]),
	format('Server accepts the client certificate~n').
