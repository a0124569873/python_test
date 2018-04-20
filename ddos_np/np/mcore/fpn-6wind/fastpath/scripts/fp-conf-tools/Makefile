# Copyright 2014, 6WIND S.A.

PYTHON := python

all: sdist

clean:
	find . -name "*.py[co]" -exec rm '{}' \;
	rm -rf *.egg-info/ dist/ build/

VERSION := DEV

sdist:
	sed -ri -e "s/version='.+'/version='$(VERSION)'/" ./setup.py
	$(PYTHON) ./setup.py sdist

install:
	$(PYTHON) ./setup.py install

develop:
	$(PYTHON) ./setup.py develop

.PHONY: all clean sdist install develop
