#include <float.h>

#ifndef PIXMAN_PRIVATE_H
#define PIXMAN_PRIVATE_H

/*
 * The defines which are shared between C and assembly code
 */

/* bilinear interpolation precision (must be <= 8) */
#define BILINEAR_INTERPOLATION_BITS 7
#define BILINEAR_INTERPOLATION_RANGE (1 << BILINEAR_INTERPOLATION_BITS)

/*
 * C specific part
 */

#ifndef __ASSEMBLER__

#ifndef PACKAGE
#  error config.h must be included before pixman-private.h
#endif

#define PIXMAN_DISABLE_DEPRECATED
#define PIXMAN_USE_INTERNAL_API

#include "pixman.h"
#include <time.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>

#include "pixman-compiler.h"

/* Misc macros */

#ifndef FALSE
#   define FALSE 0
#endif

#ifndef TRUE
#   define TRUE 1
#endif

#ifndef MIN
#  define MIN(a, b) ((a < b) ? a : b)
#endif

#ifndef MAX
#  define MAX(a, b) ((a > b) ? a : b)
#endif

/* Integer division that rounds towards -infinity */
#define DIV(a, b)					   \
    ((((a) < 0) == ((b) < 0)) ? (a) / (b) :                \
     ((a) - (b) + 1 - (((b) < 0) << 1)) / (b))

/* Modulus that produces the remainder wrt. DIV */
#define MOD(a, b) ((a) < 0 ? ((b) - ((-(a) - 1) % (b))) - 1 : (a) % (b))

#define CLIP(v, low, high) ((v) < (low) ? (low) : ((v) > (high) ? (high) : (v)))

#define FLOAT_IS_ZERO(f)     (-FLT_MIN < (f) && (f) < FLT_MIN)

/*
 * Various debugging code
 */

#undef DEBUG

#define COMPILE_TIME_ASSERT(x)						\
    do { typedef int compile_time_assertion [(x)?1:-1]; } while (0)

/* Turn on debugging depending on what type of release this is
 */
#if (((PIXMAN_VERSION_MICRO % 2) == 0) && ((PIXMAN_VERSION_MINOR % 2) == 1))

/* Debugging gets turned on for development releases because these
 * are the things that end up in bleeding edge distributions such
 * as Rawhide etc.
 *
 * For performance reasons we don't turn it on for stable releases or
 * random git checkouts. (Random git checkouts are often used for
 * performance work).
 */

#    define DEBUG

#endif

void
_pixman_log_error (const char *function, const char *message);

#define return_if_fail(expr)                                            \
    do                                                                  \
    {                                                                   \
	if (unlikely (!(expr)))                                         \
	{								\
	    _pixman_log_error (FUNC, "The expression " # expr " was false"); \
	    return;							\
	}								\
    }                                                                   \
    while (0)

#define return_val_if_fail(expr, retval)                                \
    do                                                                  \
    {                                                                   \
	if (unlikely (!(expr)))                                         \
	{								\
	    _pixman_log_error (FUNC, "The expression " # expr " was false"); \
	    return (retval);						\
	}								\
    }                                                                   \
    while (0)

#define critical_if_fail(expr)						\
    do									\
    {									\
	if (unlikely (!(expr)))                                         \
	    _pixman_log_error (FUNC, "The expression " # expr " was false"); \
    }									\
    while (0)

/*
 * Timers
 */

#ifdef PIXMAN_TIMERS

static inline uint64_t
oil_profile_stamp_rdtsc (void)
{
    uint32_t hi, lo;

    __asm__ __volatile__ ("rdtsc\n" : "=a" (lo), "=d" (hi));

    return lo | (((uint64_t)hi) << 32);
}

#define OIL_STAMP oil_profile_stamp_rdtsc

typedef struct pixman_timer_t pixman_timer_t;

struct pixman_timer_t
{
    int             initialized;
    const char *    name;
    uint64_t        n_times;
    uint64_t        total;
    pixman_timer_t *next;
};

extern int timer_defined;

void pixman_timer_register (pixman_timer_t *timer);

#define TIMER_BEGIN(tname)                                              \
    {                                                                   \
	static pixman_timer_t timer ## tname;                           \
	uint64_t              begin ## tname;                           \
        								\
	if (!timer ## tname.initialized)				\
	{                                                               \
	    timer ## tname.initialized = 1;				\
	    timer ## tname.name = # tname;				\
	    pixman_timer_register (&timer ## tname);			\
	}                                                               \
									\
	timer ## tname.n_times++;					\
	begin ## tname = OIL_STAMP ();

#define TIMER_END(tname)                                                \
    timer ## tname.total += OIL_STAMP () - begin ## tname;		\
    }

#else

#define TIMER_BEGIN(tname)
#define TIMER_END(tname)

#endif /* PIXMAN_TIMERS */

#endif /* __ASSEMBLER__ */

#endif /* PIXMAN_PRIVATE_H */
