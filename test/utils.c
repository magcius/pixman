#define _GNU_SOURCE

#include "utils.h"
#include <math.h>
#include <signal.h>
#include <stdlib.h>

#ifdef HAVE_GETTIMEOFDAY
#include <sys/time.h>
#else
#include <time.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#ifdef HAVE_FENV_H
#include <fenv.h>
#endif

#ifdef HAVE_LIBPNG
#include <png.h>
#endif

/* Random number generator state
 */

prng_t prng_state_data;
prng_t *prng_state;

/*----------------------------------------------------------------------------*\
 *  CRC-32 version 2.0.0 by Craig Bruce, 2006-04-29.
 *
 *  This program generates the CRC-32 values for the files named in the
 *  command-line arguments.  These are the same CRC-32 values used by GZIP,
 *  PKZIP, and ZMODEM.  The Crc32_ComputeBuf () can also be detached and
 *  used independently.
 *
 *  THIS PROGRAM IS PUBLIC-DOMAIN SOFTWARE.
 *
 *  Based on the byte-oriented implementation "File Verification Using CRC"
 *  by Mark R. Nelson in Dr. Dobb's Journal, May 1992, pp. 64-67.
 *
 *  v1.0.0: original release.
 *  v1.0.1: fixed printf formats.
 *  v1.0.2: fixed something else.
 *  v1.0.3: replaced CRC constant table by generator function.
 *  v1.0.4: reformatted code, made ANSI C.  1994-12-05.
 *  v2.0.0: rewrote to use memory buffer & static table, 2006-04-29.
\*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*\
 *  NAME:
 *     Crc32_ComputeBuf () - computes the CRC-32 value of a memory buffer
 *  DESCRIPTION:
 *     Computes or accumulates the CRC-32 value for a memory buffer.
 *     The 'inCrc32' gives a previously accumulated CRC-32 value to allow
 *     a CRC to be generated for multiple sequential buffer-fuls of data.
 *     The 'inCrc32' for the first buffer must be zero.
 *  ARGUMENTS:
 *     inCrc32 - accumulated CRC-32 value, must be 0 on first call
 *     buf     - buffer to compute CRC-32 value for
 *     bufLen  - number of bytes in buffer
 *  RETURNS:
 *     crc32 - computed CRC-32 value
 *  ERRORS:
 *     (no errors are possible)
\*----------------------------------------------------------------------------*/

uint32_t
compute_crc32 (uint32_t    in_crc32,
	       const void *buf,
	       size_t      buf_len)
{
    static const uint32_t crc_table[256] = {
	0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F,
	0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
	0x09B64C2B, 0x7EB17CBD,	0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2,
	0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
	0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,	0x14015C4F, 0x63066CD9,
	0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
	0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
	0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
	0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423,
	0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
	0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x01DB7106,
	0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
	0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D,
	0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
	0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
	0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
	0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7,
	0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
	0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA,
	0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
	0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
	0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
	0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84,
	0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
	0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
	0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
	0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E,
	0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
	0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55,
	0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
	0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28,
	0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
	0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F,
	0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
	0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
	0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
	0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
	0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
	0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC,
	0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
	0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693,
	0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
	0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
    };

    uint32_t              crc32;
    unsigned char *       byte_buf;
    size_t                i;

    /* accumulate crc32 for buffer */
    crc32 = in_crc32 ^ 0xFFFFFFFF;
    byte_buf = (unsigned char*) buf;

    for (i = 0; i < buf_len; i++)
	crc32 = (crc32 >> 8) ^ crc_table[(crc32 ^ byte_buf[i]) & 0xFF];

    return (crc32 ^ 0xFFFFFFFF);
}

static uint32_t
call_test_function (uint32_t    (*test_function)(int testnum, int verbose),
		    int		testnum,
		    int		verbose)
{
    uint32_t retval;

#if defined (__GNUC__) && defined (_WIN32) && (defined (__i386) || defined (__i386__))
    __asm__ (
	/* Deliberately avoid aligning the stack to 16 bytes */
	"pushl	%1\n\t"
	"pushl	%2\n\t"
	"call	*%3\n\t"
	"addl	$8, %%esp\n\t"
	: "=a" (retval)
	: "r" (verbose),
	  "r" (testnum),
	  "r" (test_function)
	: "edx", "ecx"); /* caller save registers */
#else
    retval = test_function (testnum, verbose);
#endif

    return retval;
}

/*
 * A function, which can be used as a core part of the test programs,
 * intended to detect various problems with the help of fuzzing input
 * to pixman API (according to some templates, aka "smart" fuzzing).
 * Some general information about such testing can be found here:
 * http://en.wikipedia.org/wiki/Fuzz_testing
 *
 * It may help detecting:
 *  - crashes on bad handling of valid or reasonably invalid input to
 *    pixman API.
 *  - deviations from the behavior of older pixman releases.
 *  - deviations from the behavior of the same pixman release, but
 *    configured in a different way (for example with SIMD optimizations
 *    disabled), or running on a different OS or hardware.
 *
 * The test is performed by calling a callback function a huge number
 * of times. The callback function is expected to run some snippet of
 * pixman code with pseudorandom variations to the data feeded to
 * pixman API. A result of running each callback function should be
 * some deterministic value which depends on test number (test number
 * can be used as a seed for PRNG). When 'verbose' argument is nonzero,
 * callback function is expected to print to stdout some information
 * about what it does.
 *
 * Return values from many small tests are accumulated together and
 * used as final checksum, which can be compared to some expected
 * value. Running the tests not individually, but in a batch helps
 * to reduce process start overhead and also allows to parallelize
 * testing and utilize multiple CPU cores.
 *
 * The resulting executable can be run without any arguments. In
 * this case it runs a batch of tests starting from 1 and up to
 * 'default_number_of_iterations'. The resulting checksum is
 * compared with 'expected_checksum' and FAIL or PASS verdict
 * depends on the result of this comparison.
 *
 * If the executable is run with 2 numbers provided as command line
 * arguments, they specify the starting and ending numbers for a test
 * batch.
 *
 * If the executable is run with only one number provided as a command
 * line argument, then this number is used to call the callback function
 * once, and also with verbose flag set.
 */
int
fuzzer_test_main (const char *test_name,
		  int         default_number_of_iterations,
		  uint32_t    expected_checksum,
		  uint32_t    (*test_function)(int testnum, int verbose),
		  int         argc,
		  const char *argv[])
{
    int i, n1 = 1, n2 = 0;
    uint32_t checksum = 0;
    int verbose = getenv ("VERBOSE") != NULL;

    if (argc >= 3)
    {
	n1 = atoi (argv[1]);
	n2 = atoi (argv[2]);
	if (n2 < n1)
	{
	    printf ("invalid test range\n");
	    return 1;
	}
    }
    else if (argc >= 2)
    {
	n2 = atoi (argv[1]);

	checksum = call_test_function (test_function, n2, 1);

	printf ("%d: checksum=%08X\n", n2, checksum);
	return 0;
    }
    else
    {
	n1 = 1;
	n2 = default_number_of_iterations;
    }

#ifdef USE_OPENMP
    #pragma omp parallel for reduction(+:checksum) default(none) \
					shared(n1, n2, test_function, verbose)
#endif
    for (i = n1; i <= n2; i++)
    {
	uint32_t crc = call_test_function (test_function, i, 0);
	if (verbose)
	    printf ("%d: %08X\n", i, crc);
	checksum += crc;
    }

    if (n1 == 1 && n2 == default_number_of_iterations)
    {
	if (checksum == expected_checksum)
	{
	    printf ("%s test passed (checksum=%08X)\n",
		    test_name, checksum);
	}
	else
	{
	    printf ("%s test failed! (checksum=%08X, expected %08X)\n",
		    test_name, checksum, expected_checksum);
	    return 1;
	}
    }
    else
    {
	printf ("%d-%d: checksum=%08X\n", n1, n2, checksum);
    }

    return 0;
}

/* Try to obtain current time in seconds */
double
gettime (void)
{
#ifdef HAVE_GETTIMEOFDAY
    struct timeval tv;

    gettimeofday (&tv, NULL);
    return (double)((int64_t)tv.tv_sec * 1000000 + tv.tv_usec) / 1000000.;
#else
    return (double)clock() / (double)CLOCKS_PER_SEC;
#endif
}

uint32_t
get_random_seed (void)
{
    union { double d; uint32_t u32; } t;
    t.d = gettime();
    prng_srand (t.u32);

    return prng_rand ();
}

#ifdef HAVE_SIGACTION
#ifdef HAVE_ALARM
static const char *global_msg;

static void
on_alarm (int signo)
{
    printf ("%s\n", global_msg);
    exit (1);
}
#endif
#endif

void
fail_after (int seconds, const char *msg)
{
#ifdef HAVE_SIGACTION
#ifdef HAVE_ALARM
    struct sigaction action;

    global_msg = msg;

    memset (&action, 0, sizeof (action));
    action.sa_handler = on_alarm;

    alarm (seconds);

    sigaction (SIGALRM, &action, NULL);
#endif
#endif
}

void *
aligned_malloc (size_t align, size_t size)
{
    void *result;

#ifdef HAVE_POSIX_MEMALIGN
    if (posix_memalign (&result, align, size) != 0)
      result = NULL;
#else
    result = malloc (size);
#endif

    return result;
}

#define CONVERT_15(c, is_rgb)						\
    (is_rgb?								\
     ((((c) >> 3) & 0x001f) |						\
      (((c) >> 6) & 0x03e0) |						\
      (((c) >> 9) & 0x7c00)) :						\
     (((((c) >> 16) & 0xff) * 153 +					\
       (((c) >>  8) & 0xff) * 301 +					\
       (((c)      ) & 0xff) * 58) >> 2))

double
convert_srgb_to_linear (double c)
{
    if (c <= 0.04045)
        return c / 12.92;
    else
        return pow ((c + 0.055) / 1.055, 2.4);
}

double
convert_linear_to_srgb (double c)
{
    if (c <= 0.0031308)
        return c * 12.92;
    else
        return 1.055 * pow (c, 1.0/2.4) - 0.055;
}

void
initialize_palette (pixman_indexed_t *palette, uint32_t depth, int is_rgb)
{
    int i;
    uint32_t mask = (1 << depth) - 1;

    for (i = 0; i < 32768; ++i)
	palette->ent[i] = prng_rand() & mask;

    memset (palette->rgba, 0, sizeof (palette->rgba));

    for (i = 0; i < mask + 1; ++i)
    {
	uint32_t rgba24;
 	pixman_bool_t retry;
	uint32_t i15;

	/* We filled the rgb->index map with random numbers, but we
	 * do need the ability to round trip, that is if some indexed
	 * color expands to an argb24, then the 15 bit version of that
	 * color must map back to the index. Anything else, we don't
	 * care about too much.
	 */
	do
	{
	    uint32_t old_idx;

	    rgba24 = prng_rand();
	    i15 = CONVERT_15 (rgba24, is_rgb);

	    old_idx = palette->ent[i15];
	    if (CONVERT_15 (palette->rgba[old_idx], is_rgb) == i15)
		retry = 1;
	    else
		retry = 0;
	} while (retry);

	palette->rgba[i] = rgba24;
	palette->ent[i15] = i;
    }

    for (i = 0; i < mask + 1; ++i)
    {
	assert (palette->ent[CONVERT_15 (palette->rgba[i], is_rgb)] == i);
    }
}

const char *
operator_name (pixman_op_t op)
{
    switch (op)
    {
    case PIXMAN_OP_CLEAR: return "PIXMAN_OP_CLEAR";
    case PIXMAN_OP_SRC: return "PIXMAN_OP_SRC";
    case PIXMAN_OP_DST: return "PIXMAN_OP_DST";
    case PIXMAN_OP_OVER: return "PIXMAN_OP_OVER";
    case PIXMAN_OP_OVER_REVERSE: return "PIXMAN_OP_OVER_REVERSE";
    case PIXMAN_OP_IN: return "PIXMAN_OP_IN";
    case PIXMAN_OP_IN_REVERSE: return "PIXMAN_OP_IN_REVERSE";
    case PIXMAN_OP_OUT: return "PIXMAN_OP_OUT";
    case PIXMAN_OP_OUT_REVERSE: return "PIXMAN_OP_OUT_REVERSE";
    case PIXMAN_OP_ATOP: return "PIXMAN_OP_ATOP";
    case PIXMAN_OP_ATOP_REVERSE: return "PIXMAN_OP_ATOP_REVERSE";
    case PIXMAN_OP_XOR: return "PIXMAN_OP_XOR";
    case PIXMAN_OP_ADD: return "PIXMAN_OP_ADD";
    case PIXMAN_OP_SATURATE: return "PIXMAN_OP_SATURATE";

    case PIXMAN_OP_DISJOINT_CLEAR: return "PIXMAN_OP_DISJOINT_CLEAR";
    case PIXMAN_OP_DISJOINT_SRC: return "PIXMAN_OP_DISJOINT_SRC";
    case PIXMAN_OP_DISJOINT_DST: return "PIXMAN_OP_DISJOINT_DST";
    case PIXMAN_OP_DISJOINT_OVER: return "PIXMAN_OP_DISJOINT_OVER";
    case PIXMAN_OP_DISJOINT_OVER_REVERSE: return "PIXMAN_OP_DISJOINT_OVER_REVERSE";
    case PIXMAN_OP_DISJOINT_IN: return "PIXMAN_OP_DISJOINT_IN";
    case PIXMAN_OP_DISJOINT_IN_REVERSE: return "PIXMAN_OP_DISJOINT_IN_REVERSE";
    case PIXMAN_OP_DISJOINT_OUT: return "PIXMAN_OP_DISJOINT_OUT";
    case PIXMAN_OP_DISJOINT_OUT_REVERSE: return "PIXMAN_OP_DISJOINT_OUT_REVERSE";
    case PIXMAN_OP_DISJOINT_ATOP: return "PIXMAN_OP_DISJOINT_ATOP";
    case PIXMAN_OP_DISJOINT_ATOP_REVERSE: return "PIXMAN_OP_DISJOINT_ATOP_REVERSE";
    case PIXMAN_OP_DISJOINT_XOR: return "PIXMAN_OP_DISJOINT_XOR";

    case PIXMAN_OP_CONJOINT_CLEAR: return "PIXMAN_OP_CONJOINT_CLEAR";
    case PIXMAN_OP_CONJOINT_SRC: return "PIXMAN_OP_CONJOINT_SRC";
    case PIXMAN_OP_CONJOINT_DST: return "PIXMAN_OP_CONJOINT_DST";
    case PIXMAN_OP_CONJOINT_OVER: return "PIXMAN_OP_CONJOINT_OVER";
    case PIXMAN_OP_CONJOINT_OVER_REVERSE: return "PIXMAN_OP_CONJOINT_OVER_REVERSE";
    case PIXMAN_OP_CONJOINT_IN: return "PIXMAN_OP_CONJOINT_IN";
    case PIXMAN_OP_CONJOINT_IN_REVERSE: return "PIXMAN_OP_CONJOINT_IN_REVERSE";
    case PIXMAN_OP_CONJOINT_OUT: return "PIXMAN_OP_CONJOINT_OUT";
    case PIXMAN_OP_CONJOINT_OUT_REVERSE: return "PIXMAN_OP_CONJOINT_OUT_REVERSE";
    case PIXMAN_OP_CONJOINT_ATOP: return "PIXMAN_OP_CONJOINT_ATOP";
    case PIXMAN_OP_CONJOINT_ATOP_REVERSE: return "PIXMAN_OP_CONJOINT_ATOP_REVERSE";
    case PIXMAN_OP_CONJOINT_XOR: return "PIXMAN_OP_CONJOINT_XOR";

    case PIXMAN_OP_MULTIPLY: return "PIXMAN_OP_MULTIPLY";
    case PIXMAN_OP_SCREEN: return "PIXMAN_OP_SCREEN";
    case PIXMAN_OP_OVERLAY: return "PIXMAN_OP_OVERLAY";
    case PIXMAN_OP_DARKEN: return "PIXMAN_OP_DARKEN";
    case PIXMAN_OP_LIGHTEN: return "PIXMAN_OP_LIGHTEN";
    case PIXMAN_OP_COLOR_DODGE: return "PIXMAN_OP_COLOR_DODGE";
    case PIXMAN_OP_COLOR_BURN: return "PIXMAN_OP_COLOR_BURN";
    case PIXMAN_OP_HARD_LIGHT: return "PIXMAN_OP_HARD_LIGHT";
    case PIXMAN_OP_SOFT_LIGHT: return "PIXMAN_OP_SOFT_LIGHT";
    case PIXMAN_OP_DIFFERENCE: return "PIXMAN_OP_DIFFERENCE";
    case PIXMAN_OP_EXCLUSION: return "PIXMAN_OP_EXCLUSION";
    case PIXMAN_OP_HSL_HUE: return "PIXMAN_OP_HSL_HUE";
    case PIXMAN_OP_HSL_SATURATION: return "PIXMAN_OP_HSL_SATURATION";
    case PIXMAN_OP_HSL_COLOR: return "PIXMAN_OP_HSL_COLOR";
    case PIXMAN_OP_HSL_LUMINOSITY: return "PIXMAN_OP_HSL_LUMINOSITY";

    case PIXMAN_OP_NONE:
	return "<invalid operator 'none'>";
    };

    return "<unknown operator>";
}

const char *
format_name (pixman_format_code_t format)
{
    switch (format)
    {
/* 32bpp formats */
    case PIXMAN_a8r8g8b8: return "a8r8g8b8";
    case PIXMAN_x8r8g8b8: return "x8r8g8b8";
    case PIXMAN_a8b8g8r8: return "a8b8g8r8";
    case PIXMAN_x8b8g8r8: return "x8b8g8r8";
    case PIXMAN_b8g8r8a8: return "b8g8r8a8";
    case PIXMAN_b8g8r8x8: return "b8g8r8x8";
    case PIXMAN_r8g8b8a8: return "r8g8b8a8";
    case PIXMAN_r8g8b8x8: return "r8g8b8x8";
    case PIXMAN_x14r6g6b6: return "x14r6g6b6";
    case PIXMAN_x2r10g10b10: return "x2r10g10b10";
    case PIXMAN_a2r10g10b10: return "a2r10g10b10";
    case PIXMAN_x2b10g10r10: return "x2b10g10r10";
    case PIXMAN_a2b10g10r10: return "a2b10g10r10";

/* sRGB formats */
    case PIXMAN_a8r8g8b8_sRGB: return "a8r8g8b8_sRGB";

/* 24bpp formats */
    case PIXMAN_r8g8b8: return "r8g8b8";
    case PIXMAN_b8g8r8: return "b8g8r8";

/* 16bpp formats */
    case PIXMAN_r5g6b5: return "r5g6b5";
    case PIXMAN_b5g6r5: return "b5g6r5";

    case PIXMAN_a1r5g5b5: return "a1r5g5b5";
    case PIXMAN_x1r5g5b5: return "x1r5g5b5";
    case PIXMAN_a1b5g5r5: return "a1b5g5r5";
    case PIXMAN_x1b5g5r5: return "x1b5g5r5";
    case PIXMAN_a4r4g4b4: return "a4r4g4b4";
    case PIXMAN_x4r4g4b4: return "x4r4g4b4";
    case PIXMAN_a4b4g4r4: return "a4b4g4r4";
    case PIXMAN_x4b4g4r4: return "x4b4g4r4";

/* 8bpp formats */
    case PIXMAN_a8: return "a8";
    case PIXMAN_r3g3b2: return "r3g3b2";
    case PIXMAN_b2g3r3: return "b2g3r3";
    case PIXMAN_a2r2g2b2: return "a2r2g2b2";
    case PIXMAN_a2b2g2r2: return "a2b2g2r2";

#if 0
    case PIXMAN_x4c4: return "x4c4";
    case PIXMAN_g8: return "g8";
#endif
    case PIXMAN_c8: return "x4c4 / c8";
    case PIXMAN_x4g4: return "x4g4 / g8";

    case PIXMAN_x4a4: return "x4a4";

/* 4bpp formats */
    case PIXMAN_a4: return "a4";
    case PIXMAN_r1g2b1: return "r1g2b1";
    case PIXMAN_b1g2r1: return "b1g2r1";
    case PIXMAN_a1r1g1b1: return "a1r1g1b1";
    case PIXMAN_a1b1g1r1: return "a1b1g1r1";

    case PIXMAN_c4: return "c4";
    case PIXMAN_g4: return "g4";

/* 1bpp formats */
    case PIXMAN_a1: return "a1";

    case PIXMAN_g1: return "g1";

/* YUV formats */
    case PIXMAN_yuy2: return "yuy2";
    case PIXMAN_yv12: return "yv12";
    };

    return "<unknown format>";
};

static double
calc_op (pixman_op_t op, double src, double dst, double srca, double dsta)
{
#define mult_chan(src, dst, Fa, Fb) MIN ((src) * (Fa) + (dst) * (Fb), 1.0)

    double Fa, Fb;

    switch (op)
    {
    case PIXMAN_OP_CLEAR:
    case PIXMAN_OP_DISJOINT_CLEAR:
    case PIXMAN_OP_CONJOINT_CLEAR:
	return mult_chan (src, dst, 0.0, 0.0);

    case PIXMAN_OP_SRC:
    case PIXMAN_OP_DISJOINT_SRC:
    case PIXMAN_OP_CONJOINT_SRC:
	return mult_chan (src, dst, 1.0, 0.0);

    case PIXMAN_OP_DST:
    case PIXMAN_OP_DISJOINT_DST:
    case PIXMAN_OP_CONJOINT_DST:
	return mult_chan (src, dst, 0.0, 1.0);

    case PIXMAN_OP_OVER:
	return mult_chan (src, dst, 1.0, 1.0 - srca);

    case PIXMAN_OP_OVER_REVERSE:
	return mult_chan (src, dst, 1.0 - dsta, 1.0);

    case PIXMAN_OP_IN:
	return mult_chan (src, dst, dsta, 0.0);

    case PIXMAN_OP_IN_REVERSE:
	return mult_chan (src, dst, 0.0, srca);

    case PIXMAN_OP_OUT:
	return mult_chan (src, dst, 1.0 - dsta, 0.0);

    case PIXMAN_OP_OUT_REVERSE:
	return mult_chan (src, dst, 0.0, 1.0 - srca);

    case PIXMAN_OP_ATOP:
	return mult_chan (src, dst, dsta, 1.0 - srca);

    case PIXMAN_OP_ATOP_REVERSE:
	return mult_chan (src, dst, 1.0 - dsta,  srca);

    case PIXMAN_OP_XOR:
	return mult_chan (src, dst, 1.0 - dsta, 1.0 - srca);

    case PIXMAN_OP_ADD:
	return mult_chan (src, dst, 1.0, 1.0);

    case PIXMAN_OP_SATURATE:
    case PIXMAN_OP_DISJOINT_OVER_REVERSE:
	if (srca == 0.0)
	    Fa = 1.0;
	else
	    Fa = MIN (1.0, (1.0 - dsta) / srca);
	return mult_chan (src, dst, Fa, 1.0);

    case PIXMAN_OP_DISJOINT_OVER:
	if (dsta == 0.0)
	    Fb = 1.0;
	else
	    Fb = MIN (1.0, (1.0 - srca) / dsta);
	return mult_chan (src, dst, 1.0, Fb);

    case PIXMAN_OP_DISJOINT_IN:
	if (srca == 0.0)
	    Fa = 0.0;
	else
	    Fa = MAX (0.0, 1.0 - (1.0 - dsta) / srca);
	return mult_chan (src, dst, Fa, 0.0);

    case PIXMAN_OP_DISJOINT_IN_REVERSE:
	if (dsta == 0.0)
	    Fb = 0.0;
	else
	    Fb = MAX (0.0, 1.0 - (1.0 - srca) / dsta);
	return mult_chan (src, dst, 0.0, Fb);

    case PIXMAN_OP_DISJOINT_OUT:
	if (srca == 0.0)
	    Fa = 1.0;
	else
	    Fa = MIN (1.0, (1.0 - dsta) / srca);
	return mult_chan (src, dst, Fa, 0.0);

    case PIXMAN_OP_DISJOINT_OUT_REVERSE:
	if (dsta == 0.0)
	    Fb = 1.0;
	else
	    Fb = MIN (1.0, (1.0 - srca) / dsta);
	return mult_chan (src, dst, 0.0, Fb);

    case PIXMAN_OP_DISJOINT_ATOP:
	if (srca == 0.0)
	    Fa = 0.0;
	else
	    Fa = MAX (0.0, 1.0 - (1.0 - dsta) / srca);
	if (dsta == 0.0)
	    Fb = 1.0;
	else
	    Fb = MIN (1.0, (1.0 - srca) / dsta);
	return mult_chan (src, dst, Fa, Fb);

    case PIXMAN_OP_DISJOINT_ATOP_REVERSE:
	if (srca == 0.0)
	    Fa = 1.0;
	else
	    Fa = MIN (1.0, (1.0 - dsta) / srca);
	if (dsta == 0.0)
	    Fb = 0.0;
	else
	    Fb = MAX (0.0, 1.0 - (1.0 - srca) / dsta);
	return mult_chan (src, dst, Fa, Fb);

    case PIXMAN_OP_DISJOINT_XOR:
	if (srca == 0.0)
	    Fa = 1.0;
	else
	    Fa = MIN (1.0, (1.0 - dsta) / srca);
	if (dsta == 0.0)
	    Fb = 1.0;
	else
	    Fb = MIN (1.0, (1.0 - srca) / dsta);
	return mult_chan (src, dst, Fa, Fb);

    case PIXMAN_OP_CONJOINT_OVER:
	if (dsta == 0.0)
	    Fb = 0.0;
	else
	    Fb = MAX (0.0, 1.0 - srca / dsta);
	return mult_chan (src, dst, 1.0, Fb);

    case PIXMAN_OP_CONJOINT_OVER_REVERSE:
	if (srca == 0.0)
	    Fa = 0.0;
	else
	    Fa = MAX (0.0, 1.0 - dsta / srca);
	return mult_chan (src, dst, Fa, 1.0);

    case PIXMAN_OP_CONJOINT_IN:
	if (srca == 0.0)
	    Fa = 1.0;
	else
	    Fa = MIN (1.0, dsta / srca);
	return mult_chan (src, dst, Fa, 0.0);

    case PIXMAN_OP_CONJOINT_IN_REVERSE:
	if (dsta == 0.0)
	    Fb = 1.0;
	else
	    Fb = MIN (1.0, srca / dsta);
	return mult_chan (src, dst, 0.0, Fb);

    case PIXMAN_OP_CONJOINT_OUT:
	if (srca == 0.0)
	    Fa = 0.0;
	else
	    Fa = MAX (0.0, 1.0 - dsta / srca);
	return mult_chan (src, dst, Fa, 0.0);

    case PIXMAN_OP_CONJOINT_OUT_REVERSE:
	if (dsta == 0.0)
	    Fb = 0.0;
	else
	    Fb = MAX (0.0, 1.0 - srca / dsta);
	return mult_chan (src, dst, 0.0, Fb);

    case PIXMAN_OP_CONJOINT_ATOP:
	if (srca == 0.0)
	    Fa = 1.0;
	else
	    Fa = MIN (1.0, dsta / srca);
	if (dsta == 0.0)
	    Fb = 0.0;
	else
	    Fb = MAX (0.0, 1.0 - srca / dsta);
	return mult_chan (src, dst, Fa, Fb);

    case PIXMAN_OP_CONJOINT_ATOP_REVERSE:
	if (srca == 0.0)
	    Fa = 0.0;
	else
	    Fa = MAX (0.0, 1.0 - dsta / srca);
	if (dsta == 0.0)
	    Fb = 1.0;
	else
	    Fb = MIN (1.0, srca / dsta);
	return mult_chan (src, dst, Fa, Fb);

    case PIXMAN_OP_CONJOINT_XOR:
	if (srca == 0.0)
	    Fa = 0.0;
	else
	    Fa = MAX (0.0, 1.0 - dsta / srca);
	if (dsta == 0.0)
	    Fb = 0.0;
	else
	    Fb = MAX (0.0, 1.0 - srca / dsta);
	return mult_chan (src, dst, Fa, Fb);

    case PIXMAN_OP_MULTIPLY:
    case PIXMAN_OP_SCREEN:
    case PIXMAN_OP_OVERLAY:
    case PIXMAN_OP_DARKEN:
    case PIXMAN_OP_LIGHTEN:
    case PIXMAN_OP_COLOR_DODGE:
    case PIXMAN_OP_COLOR_BURN:
    case PIXMAN_OP_HARD_LIGHT:
    case PIXMAN_OP_SOFT_LIGHT:
    case PIXMAN_OP_DIFFERENCE:
    case PIXMAN_OP_EXCLUSION:
    case PIXMAN_OP_HSL_HUE:
    case PIXMAN_OP_HSL_SATURATION:
    case PIXMAN_OP_HSL_COLOR:
    case PIXMAN_OP_HSL_LUMINOSITY:
    default:
	abort();
	return 0; /* silence MSVC */
    }
#undef mult_chan
}

void
do_composite (pixman_op_t op,
	      const color_t *src,
	      const color_t *mask,
	      const color_t *dst,
	      color_t *result,
	      pixman_bool_t component_alpha)
{
    color_t srcval, srcalpha;

    if (mask == NULL)
    {
	srcval = *src;

	srcalpha.r = src->a;
	srcalpha.g = src->a;
	srcalpha.b = src->a;
	srcalpha.a = src->a;
    }
    else if (component_alpha)
    {
	srcval.r = src->r * mask->r;
	srcval.g = src->g * mask->g;
	srcval.b = src->b * mask->b;
	srcval.a = src->a * mask->a;

	srcalpha.r = src->a * mask->r;
	srcalpha.g = src->a * mask->g;
	srcalpha.b = src->a * mask->b;
	srcalpha.a = src->a * mask->a;
    }
    else
    {
	srcval.r = src->r * mask->a;
	srcval.g = src->g * mask->a;
	srcval.b = src->b * mask->a;
	srcval.a = src->a * mask->a;

	srcalpha.r = src->a * mask->a;
	srcalpha.g = src->a * mask->a;
	srcalpha.b = src->a * mask->a;
	srcalpha.a = src->a * mask->a;
    }

    result->r = calc_op (op, srcval.r, dst->r, srcalpha.r, dst->a);
    result->g = calc_op (op, srcval.g, dst->g, srcalpha.g, dst->a);
    result->b = calc_op (op, srcval.b, dst->b, srcalpha.b, dst->a);
    result->a = calc_op (op, srcval.a, dst->a, srcalpha.a, dst->a);
}

static double
round_channel (double p, int m)
{
    int t;
    double r;

    t = p * ((1 << m));
    t -= t >> m;

    r = t / (double)((1 << m) - 1);

    return r;
}

void
round_color (pixman_format_code_t format, color_t *color)
{
    if (PIXMAN_FORMAT_R (format) == 0)
    {
	color->r = 0.0;
	color->g = 0.0;
	color->b = 0.0;
    }
    else
    {
	color->r = round_channel (color->r, PIXMAN_FORMAT_R (format));
	color->g = round_channel (color->g, PIXMAN_FORMAT_G (format));
	color->b = round_channel (color->b, PIXMAN_FORMAT_B (format));
    }

    if (PIXMAN_FORMAT_A (format) == 0)
	color->a = 1;
    else
	color->a = round_channel (color->a, PIXMAN_FORMAT_A (format));
}

/* Check whether @pixel is a valid quantization of the a, r, g, b
 * parameters. Some slack is permitted.
 */
void
pixel_checker_init (pixel_checker_t *checker, pixman_format_code_t format)
{
    assert (PIXMAN_FORMAT_VIS (format));

    checker->format = format;

    switch (PIXMAN_FORMAT_TYPE (format))
    {
    case PIXMAN_TYPE_A:
	checker->bs = 0;
	checker->gs = 0;
	checker->rs = 0;
	checker->as = 0;
	break;

    case PIXMAN_TYPE_ARGB:
    case PIXMAN_TYPE_ARGB_SRGB:
	checker->bs = 0;
	checker->gs = checker->bs + PIXMAN_FORMAT_B (format);
	checker->rs = checker->gs + PIXMAN_FORMAT_G (format);
	checker->as = checker->rs + PIXMAN_FORMAT_R (format);
	break;

    case PIXMAN_TYPE_ABGR:
	checker->rs = 0;
	checker->gs = checker->rs + PIXMAN_FORMAT_R (format);
	checker->bs = checker->gs + PIXMAN_FORMAT_G (format);
	checker->as = checker->bs + PIXMAN_FORMAT_B (format);
	break;

    case PIXMAN_TYPE_BGRA:
	/* With BGRA formats we start counting at the high end of the pixel */
	checker->bs = PIXMAN_FORMAT_BPP (format) - PIXMAN_FORMAT_B (format);
	checker->gs = checker->bs - PIXMAN_FORMAT_B (format);
	checker->rs = checker->gs - PIXMAN_FORMAT_G (format);
	checker->as = checker->rs - PIXMAN_FORMAT_R (format);
	break;

    case PIXMAN_TYPE_RGBA:
	/* With BGRA formats we start counting at the high end of the pixel */
	checker->rs = PIXMAN_FORMAT_BPP (format) - PIXMAN_FORMAT_R (format);
	checker->gs = checker->rs - PIXMAN_FORMAT_R (format);
	checker->bs = checker->gs - PIXMAN_FORMAT_G (format);
	checker->as = checker->bs - PIXMAN_FORMAT_B (format);
	break;

    default:
	assert (0);
	break;
    }

    checker->am = ((1 << PIXMAN_FORMAT_A (format)) - 1) << checker->as;
    checker->rm = ((1 << PIXMAN_FORMAT_R (format)) - 1) << checker->rs;
    checker->gm = ((1 << PIXMAN_FORMAT_G (format)) - 1) << checker->gs;
    checker->bm = ((1 << PIXMAN_FORMAT_B (format)) - 1) << checker->bs;

    checker->aw = PIXMAN_FORMAT_A (format);
    checker->rw = PIXMAN_FORMAT_R (format);
    checker->gw = PIXMAN_FORMAT_G (format);
    checker->bw = PIXMAN_FORMAT_B (format);
}

void
pixel_checker_split_pixel (const pixel_checker_t *checker, uint32_t pixel,
			   int *a, int *r, int *g, int *b)
{
    *a = (pixel & checker->am) >> checker->as;
    *r = (pixel & checker->rm) >> checker->rs;
    *g = (pixel & checker->gm) >> checker->gs;
    *b = (pixel & checker->bm) >> checker->bs;
}

void
pixel_checker_get_masks (const pixel_checker_t *checker,
                         uint32_t              *am,
                         uint32_t              *rm,
                         uint32_t              *gm,
                         uint32_t              *bm)
{
    if (am)
        *am = checker->am;
    if (rm)
        *rm = checker->rm;
    if (gm)
        *gm = checker->gm;
    if (bm)
        *bm = checker->bm;
}

void
pixel_checker_convert_pixel_to_color (const pixel_checker_t *checker,
                                      uint32_t pixel, color_t *color)
{
    int a, r, g, b;

    pixel_checker_split_pixel (checker, pixel, &a, &r, &g, &b);

    if (checker->am == 0)
        color->a = 1.0;
    else
        color->a = a / (double)(checker->am >> checker->as);

    if (checker->rm == 0)
        color->r = 0.0;
    else
        color->r = r / (double)(checker->rm >> checker->rs);

    if (checker->gm == 0)
        color->g = 0.0;
    else
        color->g = g / (double)(checker->gm >> checker->gs);

    if (checker->bm == 0)
        color->b = 0.0;
    else
        color->b = b / (double)(checker->bm >> checker->bs);

    if (PIXMAN_FORMAT_TYPE (checker->format) == PIXMAN_TYPE_ARGB_SRGB)
    {
	color->r = convert_srgb_to_linear (color->r);
	color->g = convert_srgb_to_linear (color->g);
	color->b = convert_srgb_to_linear (color->b);
    }
}

static int32_t
convert (double v, uint32_t width, uint32_t mask, uint32_t shift, double def)
{
    int32_t r;

    if (!mask)
	v = def;

    r = (v * ((mask >> shift) + 1));
    r -= r >> width;

    return r;
}

static void
get_limits (const pixel_checker_t *checker, double limit,
	    color_t *color,
	    int *ao, int *ro, int *go, int *bo)
{
    color_t tmp;

    if (PIXMAN_FORMAT_TYPE (checker->format) == PIXMAN_TYPE_ARGB_SRGB)
    {
	tmp.a = color->a;
	tmp.r = convert_linear_to_srgb (color->r);
	tmp.g = convert_linear_to_srgb (color->g);
	tmp.b = convert_linear_to_srgb (color->b);

	color = &tmp;
    }
    
    *ao = convert (color->a + limit, checker->aw, checker->am, checker->as, 1.0);
    *ro = convert (color->r + limit, checker->rw, checker->rm, checker->rs, 0.0);
    *go = convert (color->g + limit, checker->gw, checker->gm, checker->gs, 0.0);
    *bo = convert (color->b + limit, checker->bw, checker->bm, checker->bs, 0.0);
}

/* The acceptable deviation in units of [0.0, 1.0]
 */
#define DEVIATION (0.0064)

void
pixel_checker_get_max (const pixel_checker_t *checker, color_t *color,
		       int *am, int *rm, int *gm, int *bm)
{
    get_limits (checker, DEVIATION, color, am, rm, gm, bm);
}

void
pixel_checker_get_min (const pixel_checker_t *checker, color_t *color,
		       int *am, int *rm, int *gm, int *bm)
{
    get_limits (checker, - DEVIATION, color, am, rm, gm, bm);
}

pixman_bool_t
pixel_checker_check (const pixel_checker_t *checker, uint32_t pixel,
		     color_t *color)
{
    int32_t a_lo, a_hi, r_lo, r_hi, g_lo, g_hi, b_lo, b_hi;
    int32_t ai, ri, gi, bi;
    pixman_bool_t result;

    pixel_checker_get_min (checker, color, &a_lo, &r_lo, &g_lo, &b_lo);
    pixel_checker_get_max (checker, color, &a_hi, &r_hi, &g_hi, &b_hi);
    pixel_checker_split_pixel (checker, pixel, &ai, &ri, &gi, &bi);

    result =
	a_lo <= ai && ai <= a_hi	&&
	r_lo <= ri && ri <= r_hi	&&
	g_lo <= gi && gi <= g_hi	&&
	b_lo <= bi && bi <= b_hi;

    return result;
}
