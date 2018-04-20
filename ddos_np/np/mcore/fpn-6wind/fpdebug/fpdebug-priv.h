/*
 * Copyright(c) 2011 6WIND
 */

#ifdef __FastPath__
#define fpdebug_printf printf
#define fpdebug_fprintf(x, args...) fpdebug_printf(args)
#else
#define fpdebug_printf printf
#define fpdebug_fprintf fprintf
#endif

extern int gettokens(char *s);
extern const char *fpdebug_inet_ntop(int af, const void *src, char *dst,
				     size_t size);
extern int fpdebug_inet_pton(int af, const char *src, void *dst);

extern int string2mac(const char *str, uint8_t *mac);

#define FPDEBUG_MAX_ARGS 128
extern char *chargv[FPDEBUG_MAX_ARGS];
extern char prompt[16];
extern uint16_t default_vrfid;
extern char *cur_command; /* command beeing executed */
extern int s_nfpc;
extern int f_colocalized;

extern int fpdebug_send_to_fp(char *tok);
