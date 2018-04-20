APP = simple-net-client
LIST = $(APP)

CC ?= gcc

VPATH = $(S)

CFLAGS += -W -Wall -Werror -O0 -g

SRCS := simple-net-client.c

OBJS := $(SRCS:%.c=%.o)
DEPS := $(SRCS:%.c=%.d)

all: $(LIST)

-include $(DEPS)

$(APP): $(OBJS)
	$(CC) $(LDFLAGS) $(EXTRA_LDFLAGS) -o $@ $(OBJS)

%.o: %.c
	$(CC) -Wp,-MD,$(@:%.o=%.d) $(CFLAGS) $(EXTRA_CFLAGS) -o $@ -c $<

clean:
	rm -f $(OBJS) $(DEPS) $(APP)

install-devel: $(DESTDIR)/$(APP)

install-target: $(DESTDIR)/$(APP)

$(DESTDIR)/$(APP): $(APP)
	install -D $< $@

.PHONY: all clean
