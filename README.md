# router-plus-portal #

[![Build Status](https://travis-ci.org/router-plus-portal/router-plus-portal-gateway.svg?branch=master)](https://travis-ci.org/router-plus-portal/router-plus-portal-gateway)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/4595/badge.svg)](https://scan.coverity.com/projects/4595)

The WiFi Guard Dog project is a complete and embeddable captive portal
solution for wireless community groups or individuals who wish to open a
free hotspot while still preventing abuse of their Internet connection.

More information and the old issue tracker can be found on
[dev.router-plus-portal.org][homepage].
Nowadays, development happens on [GitHub][github].


## router-plus-portal Gateway ##

router-plus-portal consists of two parts:

* auth server
* client daemon (the gateway)

This repository contains the client daemon. The client typically runs on
embedded hardware, e.g. the hotspot itself. The client is responsible for
redirecting the user to the auth server where they may authenticate
themselves. Depending on the response of the auth server, the client
lifts the access restrictions for the user.
Client and server speak the [router-plus-portal Protocol Version 1][protov1],
with Version 2 being a draft which has not been implemented so far.
A detailed description of the login process involving user,
client and server is available as a [flow diagram][flowdia].

## Install ##

See the [FAQ][faq].

## Contributing ##

See [README.developers.txt][devdoc].


## License ##
The project's software is released under the GPL license and is copyrighted
by its respective owners. See COPYING for details.

[homepage]: http://dev.router-plus-portal.org/
[github]: https://github.com/router-plus-portal/
[protov1]: http://dev.router-plus-portal.org/wiki/doc/developer/router-plus-portalProtocol_V1
[flowdia]: http://dev.router-plus-portal.org/wiki/doc/developer/FlowDiagram
[devdoc]: doc/README.developers.txt
[faq]: FAQ
