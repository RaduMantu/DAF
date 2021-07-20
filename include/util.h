#include <stdio.h>      /* fprintf  */
#include <stdlib.h>     /* exit     */
#include <errno.h>      /* errno    */
#include <string.h>     /* strerror */

#ifndef _UTIL_H
#define _UTIL_H

/* compiler hints for branch prediciton */
#ifndef likely
#define likely(x)       __builtin_expect((x),1)
#endif

#ifndef unlikely
#define unlikely(x)     __builtin_expect((x),0)
#endif


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

#endif

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

/* [warning] on assertion, continue */
#define CONT(assertion, msg...) \
    do {                        \
        if (assertion) {        \
            WAR(msg);           \
            continue;           \
        }                       \
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

