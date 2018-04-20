/* Copyright 2014, 6WIND S.A. */

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "fp-fork.h"

#ifdef CONFIG_MCORE_FPVI
/* fds array used to communicate from child to parent */
static int syncpipe[2];
#endif

/*
 * Fork. Child returns immediately, parent waits for notification to exit.
 * Called early in main() before fpn_sdk_init().
 *
 * Returns < 0 if error happens.
 */
int fp_fork(void)
{
/* if CONFIG_MCORE_FPVI is undef, it means standalone FP.
 * Do not daemonize in that case */
#ifdef CONFIG_MCORE_FPVI
	int ret;

	/* create a pipe() */
	if (pipe(syncpipe) < 0)
		return -1;

	ret = fork();
	if (ret < 0)
		return -1;

	if (ret != 0) {
		char forkmsg;
		int exitcode;
		pid_t pid = ret;

		/* in parent, close unused fd */
		close(syncpipe[1]);

		while ((ret = read(syncpipe[0], &forkmsg, 1)) == -1 && errno == EINTR)
			;

		if (ret <= 0) /* read failed or returned EOF */
			forkmsg = FP_FORKMSG_ERROR;

		switch (forkmsg) {
		case FP_FORKMSG_ERROR:
			switch (waitpid(pid, &exitcode, WNOHANG)) {
			case 0:
				/* child is still alive, kill it and wait */
				kill(pid, SIGKILL);
				waitpid(pid, NULL, 0);
				/* no break to fallback in next case */
			case -1:
				exitcode = 1;
				break;
			default:
				exitcode = WEXITSTATUS(exitcode);
			}
			break;
		case FP_FORKMSG_WAIT:
			/* wait until the child exits */
			while ((ret = waitpid(pid, &exitcode, 0)) < 0 && errno == EINTR)
				;
			if (ret <= 0)
				exitcode = 1;
			else
				exitcode = WEXITSTATUS(exitcode);
			break;
		case FP_FORKMSG_SUCCESS:
		default:
			/* wait 50ms to let all cores enter their main loop */
			usleep(50000);
			exitcode = 0;
			break;
		}

		/* exit parent */
		exit(exitcode);
	}

	/* in child, close unused fd */
	close(syncpipe[0]);
#endif

	return 0;
}

/*
 * Called by the child to notify the parent to exit or wait. Should be called
 * in main() as late as possible (just before entering the main loop).
 *
 * Returns < 0 if error happens.
 */
int fp_fork_finalize(char forkmsg)
{
/* if CONFIG_MCORE_FPVI is undef, it means standalone FP.
 * Do not daemonize in that case */
#ifdef CONFIG_MCORE_FPVI
	int ret = write(syncpipe[1], &forkmsg, 1);

	close(syncpipe[1]);

	if (ret < 0)
		return -1;
#endif

	return 0;
}
