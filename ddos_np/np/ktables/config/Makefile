# Get environment variables
include $(ROOTDIR)/mk/6windgatelinux.own.mk

all: ktables_config.h

ktables_config.h: $(ROOTDIR)/config/.config
	grep CONFIG_KTABLES_ $(<) \
	| sed 's,\(CONFIG_KTABLES_.*\)=y.*$$,#define \1 1,' \
	| sed 's,\(CONFIG_KTABLES_.*\)=\(.*\)$$,#define \1 \2,' \
	| sed 's,\# \(CONFIG_KTABLES_.*\) is not set$$,#undef \1,' \
	> ktables_config.h

romfs:

clean:
	rm -f ktables_config.h

