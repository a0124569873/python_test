/*
 * Copyright (c) 2004, 2005 6WIND
 */

/*
 ***************************************************************
 *
 *                   API For communication between
 *             Kernel Stack (KRN) and the Core Componant (CC)
 * Note : All call from KRN to CC will imply the CC to first
 *        register the called fct, in order to keep KRN independant
 *        from CC symbol (for CC may be a loadable module)
 *        Unregister is done by calling register functions with
 *        NULL parameter(s)
 *
 * $Id: stack_cc.h,v 1.18 2005-04-27 12:11:19 andriot Exp $
 ***************************************************************
 */

#warning Use stack_cc from kernel

#include <net/stack_cc.h>

