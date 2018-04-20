#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>
#include <inttypes.h>
#ifndef likely
#define likely(x)       __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x)     __builtin_expect(!!(x), 0)
#endif
#define fpn_printf printf
#define FPN_DEFINE_SHARED(x,y) x y
#define FPN_DECLARE_SHARED(x,y) extern x y
#define FPN_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
