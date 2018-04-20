/* Copyright 2014, 6WIND S.A. */

/*
 * Fork. Child returns immediately, parent waits for notification to exit.
 * Called early in main() before fpn_sdk_init().
 *
 * Returns < 0 if error happens.
 */
int fp_fork(void);

/* Messages sent from the child to the parent */
#define FP_FORKMSG_SUCCESS       0
#define FP_FORKMSG_WAIT          1
#define FP_FORKMSG_ERROR        -1

/*
 * Called by the child to notify the parent to exit or wait. Should be called
 * in main() as late as possible (just before entering the main loop).
 *
 * Returns < 0 if error happens.
 */
int fp_fork_finalize(char forkmsg);
