# Copyright 2013 6WIND S.A.

DOC_COMPONENT = libfpu-crypto

# List of imported licenses and 6WIND copyrights (if any)
DOC_LICENSE = license.rst

# Short description (introduce also API in case of library)
DOC_OVERVIEW = overview.rst

# How to configure (files, environment variables, etc)
# DOC_USERGUIDE_CONF = conf.rst

# How it get used (dependencies, command line arguments, CLI, etc)
# It does not overlap with DOC_USERGUIDE_CONF.
DOC_USERGUIDE = userguide.rst

# Examples of application or samples using this library
# DOC_DEVEL_EXAMPLES = lib-example.rst

# API code files (files or directory)
DOC_DEVEL_API = ../include

# API-related docs integration: standalone|split
# DOC_DEVEL_API_MODE = standalone

# How to build and link with this library
# It should provide at least the required -lmylib.
# DOC_DEVEL_BUILD = lib-link.rst

# How to start make
# It should explain the build options (if any).
# For instance, if an option reduces size but decreases performance,
# it should be explained here.
DOC_SRC_BUILD = src-build.rst

# SAD - Software Architecture Document
# It provides a summary of the architecture of this software component.
# DOC_SRC_DESIGN_OVERVIEW = sad.rst

# SDD - Software Design Document
# It should explain the logic to customize the source code
# and/or the behaviour (e.g. what happens on ARP expiration).
# DOC_SRC_DESIGN_DETAILS = sdd.rst

ifndef DOC_TOOLS
# no doc build
build-help : ; @ cat $(DOC_SRC_BUILD)
clean : ; @ true
% : ; @ echo 'no rule doc-$@ - try to define DOC_TOOLS' && false

else # use doc-tools
include $(DOC_TOOLS)/mk/full.mk

help :
	@ $(MAKE) -rRs list-rules | tr ' ' '\n' | sed 's,^,    doc-,'
	@ echo '    doc-help'
	@ echo '    help'

endif
