#ifndef __NT_MACROS_H__
#define __NT_MACROS_H__


#ifdef __GNUC__
  #define nt_unlikely(x) __builtin_expect((x),0)
  #define nt_likely(x) __builtin_expect((x),1)
  #define nt_prefetch(x, ...) __builtin_prefetch(x, __VA_ARGS__)
#else
  #define nt_unlikely(x)      (x)
  #define nt_likely(x)        (x)
  #define nt_prefetch(x, ...) (x, __VA_ARGS__)
#endif


#define NT_EXIT_SUCCESS    EXIT_SUCCESS
#define NT_EXIT_FAILURE    EXIT_FAILURE
#define NT_EXIT(r)         exit(r)

#define no_argument         0
#define required_argument   1
#define optional_argument   2

#endif /* __NT_MACROS_H__ */

