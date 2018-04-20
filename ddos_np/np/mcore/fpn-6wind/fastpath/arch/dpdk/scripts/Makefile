# Copyright 2014 6WIND S.A.

all clean install install-devel:;

scripts := fast-path.sh check-fp-conf.sh check-sys-conf.sh status-fp-arch.sh
confs := fast-path.env.tmpl

BIN_SRC_FILES:=$(addprefix $(S)/, $(scripts))
ETC_SRC_FILES:=$(addprefix $(S)/, $(confs))
LIB_SRC_FILES:=

include $(DIST_FP)/mk/install_startup_files.mk
