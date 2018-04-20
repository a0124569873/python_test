# Ubuntu detection: kernel may define CONFIG_VERSION_SIGNATURE
# such like CONFIG_VERSION_SIGNATURE="Ubuntu 3.13.0-32.57-generic 3.13.11.4"
ifneq ($(findstring Ubuntu, $(CONFIG_VERSION_SIGNATURE)),)
MODULE_CFLAGS += -DUBUNTU_RELEASE
comma := ,
UBUNTU_KERNEL_CODE := $(shell echo $(CONFIG_VERSION_SIGNATURE) | \
                   cut -d' ' -f2 | cut -d'~' -f1 | cut -d- -f1,2 | tr .- $(comma))
MODULE_CFLAGS += -D"UBUNTU_KERNEL_VERSION(a,b,c,abi,upload)=(((a) << 40) + ((b) << 32) + ((c) << 24) + ((abi) << 8) + (upload))"
MODULE_CFLAGS += -D"UBUNTU_KERNEL_CODE=UBUNTU_KERNEL_VERSION($(UBUNTU_KERNEL_CODE))"
else
MODULE_CFLAGS += -UUBUNTU_RELEASE
MODULE_CFLAGS += -D"UBUNTU_KERNEL_VERSION(a,b,c,abi,upload)=0"
MODULE_CFLAGS += -DUBUNTU_KERNEL_CODE=0
endif

# Take user's flags and reset EXTRA_CFLAGS
ifneq ($(KERNELRELEASE),)
override EXTRA_CFLAGS := $(MODULE_CFLAGS) $(EXTRA_MODULE_CFLAGS) \
                         $(EXTRA_MODULE_CFLAGS_$(MODULE))

obj-m          += $(MODULE).o
ifneq ($(MODULE),$(notdir $(patsubst %.S,%,$(SRCS:%.c=%))))
$(MODULE)-objs += $(notdir $(patsubst %.S,%.o,$(SRCS:%.c=%.o)))
endif
else

include $(FPNSDK_DIR)/mk/gcc.mk

skip:=0
ifeq ($(KERNEL_BUILDROOT),)
skip:=1
else
ifeq ($(wildcard $(KERNEL_BUILDROOT)/scripts/mod/modpost),)
$(error $(KERNEL_BUILDROOT) cannot build module)
endif
endif

ifeq ($(CROSS_COMPILE),clang)
skip=1
endif

ifeq ($(skip),1)

all clean install install-target install-devel:
	@echo Skip module $(MODULE)

else

# Link the file in build dir if the source is in another component
# Assume S= gives source directory if Makefile is not present
#

S?=$(CURDIR)
MOD_MAKEF?=Makefile

all: module

# Always update sym links to handle changes of $S
# But don't make sym link if the file is present (building in source tree case)
linksrc:
	@$(foreach FILE,$(SRCS), if [ ! -f $(notdir $(FILE)) ]; then ln -nfs $(FILE) . ; fi ;)
	@[ -f Makefile ] || ln -fs $(S)/$(MOD_MAKEF) Makefile

module: linksrc
	$(Q)$(MAKE) -C $(KERNEL_BUILDROOT) M=$(CURDIR) O=$(KERNEL_BUILDROOT)

install install-target:
	$(Q)$(MAKE) -C $(KERNEL_BUILDROOT) M=$(CURDIR) O=$(KERNEL_BUILDROOT) \
		INSTALL_MOD_DIR=$(MODULE_PATH) INSTALL_MOD_PATH=$(DESTDIR) \
		DEPMOD=/bin/true modules_install

install-devel:;

# Do a make clean and remove links
clean:
	@[ ! -e Makefile ] || $(MAKE) -C $(KERNEL_BUILDROOT) M=$(CURDIR) O=$(KERNEL_BUILDROOT) clean
	@$(foreach FILE,$(SRCS), if [ -h $(notdir $(FILE)) ]; then rm -f $(notdir $(FILE)) ; fi ;)
	@[ ! -h  Makefile ] || rm -f Makefile

ifeq ($(PKG_DKMS),y)
-include $(FPNSDK_DIR)/mk/dkms.mk
endif

endif

endif
