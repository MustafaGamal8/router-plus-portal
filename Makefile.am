# $Id$

AUTOMAKE_OPTIONS = foreign

SUBDIRS = libhttpd src . doc 

docdir = ${prefix}/share/doc/router-plus-portal-@VERSION@

doc_DATA = \
  AUTHORS \
  COPYING \
  NEWS \
  README.md \
  ChangeLog
  
EXTRA_DIST = \
  FAQ \
  router-plus-portal.spec.in \
  router-plus-portal.spec \
  config \
  scripts \
  contrib \
  router-plus-portal.conf

.PHONY: doc
doc:
	$(MAKE) -C doc doc
