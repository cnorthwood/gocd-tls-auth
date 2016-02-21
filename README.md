Go.CD TLS Client Certificate Authenticator
==========================================

[![Build Status](https://travis-ci.org/cnorthwood/gocd-tls-auth.svg?branch=master)](https://travis-ci.org/cnorthwood/gocd-tls-auth)

This plugin allows users to be authenticated by TLS client certificates, when
Go.CD is behind a reverse proxy which terminates TLS and passes through the
certificate details in HTTP headers.

Deploying
---------

To start with, you'll need to [configure your Go server to use password
authentication](https://www.go.cd/documentation/user/current/configuration/dev_authentication.html).

You'll also need to configure Apache or something to terminate your SSL
connections and reverse proxy it through to Go. Apache will need to make the
certificate CN available to the upstream server under the "SSL_CLIENT_S_DN"
header. Adding a line such as below to your Apache config file will allow this:

    RequestHeader set SSL_CLIENT_S_DN "%{SSL_CLIENT_S_DN}s"
   
The httpd.conf in the apache-config folder shows a complete sample configuration.

Then, you can download the plugin from the Releases section in GitHub, then
drop it in your plugins folder in Go (e.g., `/var/lib/go-server/plugins/external`).

Once it's configured, and you've restarted Go, a new button should appear on the
login screen. Select it and it'll use your certificate to authenticate you.
You'll then need to log in to the server using the username/password in the
passwords file, and add your user as an admin. Sadly Go doesn't yet support
auth plugins for API access, so you'll need to still use the passwords file for
any machine users that access the server using the API.

Developing
----------

There's a Vagrant box which uses Apache for TLS termination and forwards to Go.
It's currently configured to require a [BBC Platform client certificate](http://www.bbc.co.uk/developer/theplatform.html)
which is probably not useful for a wider audience. Replace ca.pem in the
apache-config folder and the SSLRequire line in httpd.conf to develop using
your CA.

Run `vagrant up` then you can access your Go server at https://localhost:7443.

For the dev server, you can configure the password file to be `/vagrant/apache-config/htpasswd`.
The default username and password is "root" and "correct horse battery staple".

To build the plugin, run `mvn install`. The output should become available as a
plugin in Go (you'll need to restart Go after compiling, `vagrant ssh` then
`sudo service go-server restart`).
