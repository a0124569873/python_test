# Copyright 2014 6WIND S.A.

all clean install install-devel:;

# install scripts
scripts := fpm.sh
confs := fpm.env

BIN_SRC_FILES:=$(addprefix $(S)/,$(scripts))
ETC_SRC_FILES:=$(addprefix $(S)/,$(confs))

include $(DIST_FP)/mk/install_startup_files.mk
