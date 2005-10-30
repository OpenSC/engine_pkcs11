# Process this file with automake to create Makefile.in

MAINTAINERCLEANFILES = Makefile.in $(HTML) ChangeLog

EXTRA_DIST = README export-wiki.sh export-wiki.xsl $(HTML) index.html ChangeLog

HTML= $(shell ls $(srcdir)/*.html $(srcdir)/*.css)

index.html:
	sh $(srcdir)/export-wiki.sh $(srcdir)

ChangeLog:
	sh $(srcdir)/changelog.sh $(srcdir)
