/* Native implementation of soft float functions */
#include <math.h>
#include <stdint.h>

#if (defined(_BSD) && !defined(__APPLE__)) || defined(HOST_SOLARIS)
#include <ieeefp.h>
#define fabsf(f) ((float)fabs(f))
#else
#include <fenv.h>
#endif

/*
 * Define some C99-7.12.3 classification macros and
 *        some C99-.12.4 for Solaris systems OS less than 10,
 *        or Solaris 10 systems running GCC 3.x or less.
 *   Solaris 10 with GCC4 does not need these macros as they
 *   are defined in <iso/math_c99.h> with a compiler directive
 */
#if defined(HOST_SOLARIS) && (( HOST_SOLARIS <= 9 ) || ((HOST_SOLARIS >= 10) && (__GNUC__ <= 4)))
/*
 * C99 7.12.3 classification macros
 * and
 * C99 7.12.14 comparison macros
 *
 * ... do not work on Solaris 10 using GNU CC 3.4.x.
 * Try to workaround the missing / broken C99 math macros.
 */

#define isnormal(x)             (fpclass(x) >= FP_NZERO)
#define isgreater(x, y)         ((!unordered(x, y)) && ((x) > (y)))
#define isgreaterequal(x, y)    ((!unordered(x, y)) && ((x) >= (y)))
#define isless(x, y)            ((!unordered(x, y)) && ((x) < (y)))
#define islessequal(x, y)       ((!unordered(x, y)) && ((x) <= (y)))
#define isunordered(x,y)        unordered(x, y)
#endif

#if defined(__sun__) && !defined(NEED_LIBSUNMATH)

#ifndef isnan
# define isnan(x) \
    (sizeof (x) == sizeof (long double) ? isnan_ld (x) \
     : sizeof (x) == sizeof (double) ? isnan_d (x) \
     : isnan_f (x))
static inline int isnan_f  (float       x) { return x != x; }
static inline int isnan_d  (double      x) { return x != x; }
static inline int isnan_ld (long double x) { return x != x; }
#endif

#ifndef isinf
# define isinf(x) \
    (sizeof (x) == sizeof (long double) ? isinf_ld (x) \
     : sizeof (x) == sizeof (double) ? isinf_d (x) \
     : isinf_f (x))
static inline int isinf_f  (float       x) { return isnan (x - x); }
static inline int isinf_d  (double      x) { return isnan (x - x); }
static inline int isinf_ld (long double x) { return isnan (x - x); }
#endif
#endif

typedef float float32;
typedef double float64;
#ifdef FLOATX80
typedef long double floatx80;
#define floatx80_zero 0
#define floatx80_one 1
#define floatx80_pi 3.141592653589793
#endif
#ifdef FLOAT128
typedef long double float128;
#endif

#define float32_zero 0
#define float32_one 1
#define float32_pi 3.141592653589793

#define float64_zero 0
#define float64_one 1
#define float64_pi 3.141592653589793

typedef union {
    float32 f;
    uint32_t i;
} float32u;
typedef union {
    float64 f;
    uint64_t i;
} float64u;
#ifdef FLOATX80
typedef union {
    floatx80 f;
    struct {
        uint32_t low;
        uint32_t high;
    } i;
} floatx80u;
#endif

/*----------------------------------------------------------------------------
| Software IEC/IEEE floating-point rounding mode.
*----------------------------------------------------------------------------*/
#if (defined(_BSD) && !defined(__APPLE__)) || defined(HOST_SOLARIS)
enum {
    float_round_nearest_even = FP_RN,
    float_round_down         = FP_RM,
    float_round_up           = FP_RP,
    float_round_to_zero      = FP_RZ
};
#elif defined(__arm__)
enum {
    float_round_nearest_even = 0,
    float_round_down         = 1,
    float_round_up           = 2,
    float_round_to_zero      = 3
};
#else
enum {
    float_round_nearest_even = FE_TONEAREST,
    float_round_down         = FE_DOWNWARD,
    float_round_up           = FE_UPWARD,
    float_round_to_zero      = FE_TOWARDZERO
};
#endif

typedef struct float_status {
    signed char float_rounding_mode;
#ifdef FLOATX80
    signed char floatx80_rounding_precision;
#endif
} float_status;

void set_float_rounding_mode(int STATUS_PARAM);
#ifdef FLOATX80
void set_floatx80_rounding_precision(int STATUS_PARAM);
#endif

/*----------------------------------------------------------------------------
| Software IEC/IEEE integer-to-floating-point conversion routines.
*----------------------------------------------------------------------------*/
float32 int32_to_float32( int STATUS_PARAM);
float32 uint32_to_float32( unsigned int STATUS_PARAM);
float64 int32_to_float64( int STATUS_PARAM);
float64 uint32_to_float64( unsigned int STATUS_PARAM);
#ifdef FLOATX80
floatx80 int32_to_floatx80( int STATUS_PARAM);
#endif
#ifdef FLOAT128
float128 int32_to_float128( int STATUS_PARAM);
#endif
float32 int64_to_float32( int64_t STATUS_PARAM);
float32 uint64_to_float32( uint64_t STATUS_PARAM);
float64 int64_to_float64( int64_t STATUS_PARAM);
float64 uint64_to_float64( uint64_t v STATUS_PARAM);
#ifdef FLOATX80
floatx80 int64_to_floatx80( int64_t STATUS_PARAM);
#endif
#ifdef FLOAT128
float128 int64_to_float128( int64_t STATUS_PARAM);
#endif

/*----------------------------------------------------------------------------
| Software IEC/IEEE single-precision conversion routines.
*----------------------------------------------------------------------------*/
int float32_to_int32( float32  STATUS_PARAM);
int float32_to_int32_round_to_zero( float32  STATUS_PARAM);
unsigned int float32_to_uint32( float32 a STATUS_PARAM);
unsigned int float32_to_uint32_round_to_zero( float32 a STATUS_PARAM);
int64_t float32_to_int64( float32  STATUS_PARAM);
int64_t float32_to_int64_round_to_zero( float32  STATUS_PARAM);
float64 float32_to_float64( float32  STATUS_PARAM);
#ifdef FLOATX80
floatx80 float32_to_floatx80( float32  STATUS_PARAM);
#endif
#ifdef FLOAT128
float128 float32_to_float128( float32  STATUS_PARAM);
#endif

/*----------------------------------------------------------------------------
| Software IEC/IEEE single-precision operations.
*----------------------------------------------------------------------------*/
float32 float32_round_to_int( float32  STATUS_PARAM);
INLINE int float32_unordered_quiet( float32 a, float32 b STATUS_PARAM)
{
    return a == b;
}
INLINE int float32_eq_quiet( float32 a, float32 b STATUS_PARAM)
{
    return a == b;
}
INLINE float32 float32_add( float32 a, float32 b STATUS_PARAM)
{
    return a + b;
}
INLINE float32 float32_sub( float32 a, float32 b STATUS_PARAM)
{
    return a - b;
}
INLINE float32 float32_mul( float32 a, float32 b STATUS_PARAM)
{
    return a * b;
}
INLINE float32 float32_div( float32 a, float32 b STATUS_PARAM)
{
    return a / b;
}
float32 float32_rem( float32, float32  STATUS_PARAM);
float32 float32_sqrt( float32  STATUS_PARAM);
INLINE int float32_eq( float32 a, float32 b STATUS_PARAM)
{
    return a == b;
}
INLINE int float32_le( float32 a, float32 b STATUS_PARAM)
{
    return a <= b;
}
INLINE int float32_lt( float32 a, float32 b STATUS_PARAM)
{
    return a < b;
}
INLINE int float32_eq_signaling( float32 a, float32 b STATUS_PARAM)
{
    return a <= b && a >= b;
}
INLINE int float32_le_quiet( float32 a, float32 b STATUS_PARAM)
{
    return islessequal(a, b);
}
INLINE int float32_lt_quiet( float32 a, float32 b STATUS_PARAM)
{
    return isless(a, b);
}
INLINE int float32_unordered( float32 a, float32 b STATUS_PARAM)
{
    return isunordered(a, b);

}
int float32_compare( float32, float32 STATUS_PARAM );
int float32_compare_quiet( float32, float32 STATUS_PARAM );
int float32_is_signaling_nan( float32 );

INLINE float32 float32_abs(float32 a)
{
    return fabsf(a);
}

INLINE float32 float32_chs(float32 a)
{
    return -a;
}

/*----------------------------------------------------------------------------
| Software IEC/IEEE double-precision conversion routines.
*----------------------------------------------------------------------------*/
int float64_to_int32( float64 STATUS_PARAM );
int float64_to_int32_round_to_zero( float64 STATUS_PARAM );
unsigned int float64_to_uint32( float64 STATUS_PARAM );
unsigned int float64_to_uint32_round_to_zero( float64 STATUS_PARAM );
int64_t float64_to_int64( float64 STATUS_PARAM );
int64_t float64_to_int64_round_to_zero( float64 STATUS_PARAM );
uint64_t float64_to_uint64( float64 STATUS_PARAM );
uint64_t float64_to_uint64_round_to_zero( float64 STATUS_PARAM );
float32 float64_to_float32( float64 STATUS_PARAM );
#ifdef FLOATX80
floatx80 float64_to_floatx80( float64 STATUS_PARAM );
#endif
#ifdef FLOAT128
float128 float64_to_float128( float64 STATUS_PARAM );
#endif

/*----------------------------------------------------------------------------
| Software IEC/IEEE double-precision operations.
*----------------------------------------------------------------------------*/
float64 float64_round_to_int( float64 STATUS_PARAM );
float64 float64_trunc_to_int( float64 STATUS_PARAM );
INLINE int float64_eq_quiet( float64 a, float64 b STATUS_PARAM)
{
    return a == b;
}
INLINE int float64_unordered_quiet( float64 a, float64 b STATUS_PARAM)
{
    return a == b;
}
INLINE float64 float64_add( float64 a, float64 b STATUS_PARAM)
{
    return a + b;
}
INLINE float64 float64_sub( float64 a, float64 b STATUS_PARAM)
{
    return a - b;
}
INLINE float64 float64_mul( float64 a, float64 b STATUS_PARAM)
{
    return a * b;
}
INLINE float64 float64_div( float64 a, float64 b STATUS_PARAM)
{
    return a / b;
}
float64 float64_rem( float64, float64 STATUS_PARAM );
float64 float64_sqrt( float64 STATUS_PARAM );
INLINE int float64_eq( float64 a, float64 b STATUS_PARAM)
{
    return a == b;
}
INLINE int float64_le( float64 a, float64 b STATUS_PARAM)
{
    return a <= b;
}
INLINE int float64_lt( float64 a, float64 b STATUS_PARAM)
{
    return a < b;
}
INLINE int float64_eq_signaling( float64 a, float64 b STATUS_PARAM)
{
    return a <= b && a >= b;
}
INLINE int float64_le_quiet( float64 a, float64 b STATUS_PARAM)
{
    return islessequal(a, b);
}
INLINE int float64_lt_quiet( float64 a, float64 b STATUS_PARAM)
{
    return isless(a, b);

}
INLINE int float64_unordered( float64 a, float64 b STATUS_PARAM)
{
    return isunordered(a, b);

}
int float64_compare( float64, float64 STATUS_PARAM );
int float64_compare_quiet( float64, float64 STATUS_PARAM );
int float64_is_signaling_nan( float64 );
int float64_is_nan( float64 );

INLINE float64 float64_abs(float64 a)
{
    return fabs(a);
}

INLINE float64 float64_chs(float64 a)
{
    return -a;
}

#ifdef FLOATX80

/*----------------------------------------------------------------------------
| Software IEC/IEEE extended double-precision conversion routines.
*----------------------------------------------------------------------------*/
int floatx80_to_int32( floatx80 STATUS_PARAM );
int floatx80_to_int32_round_to_zero( floatx80 STATUS_PARAM );
int64_t floatx80_to_int64( floatx80 STATUS_PARAM);
int64_t floatx80_to_int64_round_to_zero( floatx80 STATUS_PARAM);
float32 floatx80_to_float32( floatx80 STATUS_PARAM );
float64 floatx80_to_float64( floatx80 STATUS_PARAM );
#ifdef FLOAT128
float128 floatx80_to_float128( floatx80 STATUS_PARAM );
#endif

// misc crap
INLINE void set_float_detect_tininess(int val STATUS_PARAM) { }
INLINE void set_flush_to_zero(flag val STATUS_PARAM) { }
INLINE void set_flush_inputs_to_zero(flag val STATUS_PARAM) { }
INLINE void set_default_nan_mode(flag val STATUS_PARAM) { }
INLINE int get_float_exception_flags(float_status *status)
{
        return 0;
}

/*----------------------------------------------------------------------------
| Software IEC/IEEE extended double-precision operations.
*----------------------------------------------------------------------------*/
floatx80 floatx80_round_to_int( floatx80 STATUS_PARAM );
INLINE floatx80 floatx80_scalbn( floatx80 a, int n STATUS_PARAM )
{
    return scalbnl(a, n);
}
INLINE floatx80 floatx80_is_any_nan( floatx80 a )
{
    return isnan(a);
}
INLINE floatx80 floatx80_is_zero( floatx80 a )
{
    return a != 0;
}
INLINE floatx80 floatx80_is_neg( floatx80 a )
{
    return a < 0;
}
INLINE floatx80 floatx80_add( floatx80 a, floatx80 b STATUS_PARAM)
{
    return a + b;
}
INLINE floatx80 floatx80_sub( floatx80 a, floatx80 b STATUS_PARAM)
{
    return a - b;
}
INLINE floatx80 floatx80_mul( floatx80 a, floatx80 b STATUS_PARAM)
{
    return a * b;
}
INLINE floatx80 floatx80_div( floatx80 a, floatx80 b STATUS_PARAM)
{
    return a / b;
}
floatx80 floatx80_rem( floatx80, floatx80 STATUS_PARAM );
floatx80 floatx80_sqrt( floatx80 STATUS_PARAM );
INLINE int floatx80_eq( floatx80 a, floatx80 b STATUS_PARAM)
{
    return a == b;
}
INLINE int floatx80_le( floatx80 a, floatx80 b STATUS_PARAM)
{
    return a <= b;
}
INLINE int floatx80_lt( floatx80 a, floatx80 b STATUS_PARAM)
{
    return a < b;
}
INLINE int floatx80_eq_signaling( floatx80 a, floatx80 b STATUS_PARAM)
{
    return a <= b && a >= b;
}
INLINE int floatx80_le_quiet( floatx80 a, floatx80 b STATUS_PARAM)
{
    return islessequal(a, b);
}
INLINE int floatx80_lt_quiet( floatx80 a, floatx80 b STATUS_PARAM)
{
    return isless(a, b);

}
INLINE int floatx80_unordered( floatx80 a, floatx80 b STATUS_PARAM)
{
    return isunordered(a, b);

}
int floatx80_compare( floatx80, floatx80 STATUS_PARAM );
int floatx80_compare_quiet( floatx80, floatx80 STATUS_PARAM );
int floatx80_is_signaling_nan( floatx80 );

INLINE floatx80 floatx80_abs(floatx80 a)
{
    return fabsl(a);
}

INLINE floatx80 floatx80_chs(floatx80 a)
{
    return -a;
}
#endif
