ifeq ("$(origin V)", "command line")
Q =
P = @ true
else
MAKEFLAGS += --no-print-directory
Q = @
P = @ echo
endif

# D (Debug): 0 (none) or 1 (verbose shell invocation)
ifeq '$D' '1'
OLD_SHELL := $(SHELL)
# In a rule context, target and triggering prerequisites are printed
# The command is printed thanks to -x
SHELL = $(warning $(strip \
	$(if $@, \
		Building $@ $(if $?, ($? newer)), \
		Parsing) \
	))$(OLD_SHELL) -x
endif
