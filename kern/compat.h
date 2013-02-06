/*
 * compat.h - compatibility declarations for old kernels
 */

#include <asm/cpufeature.h>

#if !defined(X86_FEATURE_EAGER_FPU)
#define use_eager_fpu() (0)
#endif

