#pragma once

#include <stdio.h>      /* fprintf      */
#include <stdint.h>     /* [u]int*_t    */
#include <stdlib.h>     /* exit         */
#include <errno.h>      /* errno        */
#include <string.h>     /* strerror     */
#include <sys/time.h>   /* gettimeofday */

/* compiler hints for branch prediciton */
#ifndef likely
#define likely(x)       __builtin_expect((x),1)
#endif

#ifndef unlikely
#define unlikely(x)     __builtin_expect((x),0)
#endif

/* `elif` keyword for brevity */
#ifndef elif
#define elif else if
#endif

/* Read Timestamp Counter macro */
#define rdtsc(eax, edx) \
    asm volatile (      \
        "rdtsc"         \
        : "=a"(eax),    \
          "=d"(edx))

/* timstamp structure (compatible with rdtsc) */
typedef union {
    uint64_t raw;
    struct {
        uint32_t low;
        uint32_t high;
    };
} tscval_t;

/* set to 0 in order to suppress DEBUG output */
#define DEBUG_EN 1

#define RED         "\033[31m"
#define RED_B       "\033[31;1m"
#define GREEN       "\033[32m"
#define GREEN_B     "\033[32;1m"
#define YELLOW      "\033[33m"
#define YELLOW_B    "\033[33;1m"
#define BLUE        "\033[34m"
#define BLUE_B      "\033[34;1m"
#define MAGENTA     "\033[35m"
#define MAGENTA_B   "\033[35;1m"
#define CYAN        "\033[36m"
#define CYAN_B      "\033[36;1m"

#define UNSET_B     "\033[2m"
#define CLR         "\033[0m"

/* [error] no assertion, just print */
#define ERROR(msg...)                                            \
    do {                                                         \
        fprintf(stdout, RED_B "[!] %s:%d ", __FILE__, __LINE__); \
        fprintf(stdout, UNSET_B msg);                            \
        fprintf(stdout, CLR "\n");                               \
    } while (0)

/* [error] on assertion, exit with -1 */
#define DIE(assertion, msg...) \
    do {                       \
        if (assertion) {       \
            ERROR(msg);        \
            exit(-1);          \
        }                      \
    } while(0)

/* [error] on assertion, jump to cleanup label */
#define GOTO(assertion, label, msg...) \
    do {                               \
        if (assertion) {               \
            ERROR(msg);                \
            goto label;                \
        }                              \
    } while (0)

/* [error] on assertion, immediately return */
#define RET(assertion, code, msg...) \
    do {                             \
        if (assertion) {             \
            ERROR(msg);              \
            return code;             \
        }                            \
    } while (0)

/* [warning] no assertion, just print */
#define WAR(msg...)                                                 \
    do {                                                            \
        fprintf(stdout, YELLOW_B "[?] %s:%d ", __FILE__, __LINE__); \
        fprintf(stdout, UNSET_B msg);                               \
        fprintf(stdout, CLR "\n");                                  \
    } while (0)

/* [warning] on assertion, do fuck all */
#define ALERT(assertion, msg...) \
    do {                         \
        if (assertion) {         \
            WAR(msg);            \
        }                        \
    } while (0)

/* [debug] no assertion, just print */
#define DEBUG(msg...)                                                 \
    do {                                                              \
        if (DEBUG_EN) {                                               \
            fprintf(stdout, BLUE_B "[-] %s:%d ", __FILE__, __LINE__); \
            fprintf(stdout, UNSET_B msg);                             \
            fprintf(stdout, CLR "\n");                                \
        }                                                             \
    } while (0)

/* [info] no assertion, just print */
#define INFO(msg...)                                               \
    do {                                                           \
        fprintf(stdout, GREEN_B "[*] %s:%d ", __FILE__, __LINE__); \
        fprintf(stdout, UNSET_B msg);                              \
        fprintf(stdout, CLR "\n");                                 \
    } while (0)


/* ARM_TIMER - marks the start of a measured operation
 *  @start : struct timeval that will hold starting time
 */
#ifdef ENABLE_STATS
#   define ARM_TIMER(start)             \
        do {                            \
            gettimeofday(&start, NULL); \
        } while (0)
#else
#   define ARM_TIMER(...)
#endif /* ENABLE_STATS */

/* UPDATE_TIMER - calculates elapsed time and increments counter
 *  @counter : variable that holds _total_ elapsed us
 *  @start   : struct timeval used with ARM_TIMER previously
 */
#ifdef ENABLE_STATS
#   define UPDATE_TIMER(counter, start)                  \
        do {                                             \
            struct timeval end;                          \
            gettimeofday(&end, NULL);                    \
            counter += (end.tv_sec - start.tv_sec) * 1e6 \
                     + (end.tv_usec - start.tv_usec);    \
        } while (0)
#else
#   define UPDATE_TIMER(...)
#endif /* ENABLE_STATS */
