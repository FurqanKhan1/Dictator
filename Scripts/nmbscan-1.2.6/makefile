VERSION=1.2.6
NAME=nmbscan
ARCHIVE=$(NAME)-$(VERSION).tar.gz

.PHONY: default archive

default: archive

archive:
	git archive --format=tar v$(VERSION) | gzip > $(ARCHIVE)
