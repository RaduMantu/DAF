#include <stdio.h>      /* fprintf */
#include <stdlib.h>     /* exit    */
#include <errno.h>      /* errno   */

#ifndef _UTIL_H
#define _UTIL_H

/* set to false to suppress DEBUG output */
#define DEBUG_EN true

#define RED      "\033[31m"
#define RED_B    "\033[31;1m"
#define GREEN    "\033[32m"
#define GREEN_B  "\033[32;1m"
#define YELLOW   "\033[33m"
#define YELLOW_B "\033[33;1m"
#define BLUE     "\033[34m"
#define BLUE_B   "\033[34;1m"

#define UNSET_B  "\033[2m"
#define CLR      "\033[0m"

/* [error] on assertion, exit with -1 */
#define DIE(assertion, msg...)                                       \
    do {                                                             \
        if (assertion) {                                             \
            fprintf(stdout, RED_B "[!] %s:%d ", __FILE__, __LINE__); \
            fprintf(stdout, UNSET_B msg);                            \
            fprintf(stdout, CLR "\n");                               \
            exit(-1);                                                \
        }                                                            \
    } while(0)

/* [error] on assertion, jump to cleanup label */
#define GOTO(assertion, label, msg...)                               \
    do {                                                             \
        if (assertion) {                                             \
            fprintf(stdout, RED_B "[!] %s:%d ", __FILE__, __LINE__); \
            fprintf(stdout, UNSET_B msg);                            \
            fprintf(stdout, CLR "\n");                               \
            goto label;                                              \
        }                                                            \
    } while (0)

/* [error] on assertion, immediately return */
#define RET(assertion, code, msg...)                                 \
    do {                                                             \
        if (assertion) {                                             \
            fprintf(stdout, RED_B "[!] %s:%d ", __FILE__, __LINE__); \
            fprintf(stdout, UNSET_B msg);                            \
            fprintf(stdout, CLR "\n");                               \
            return code;                                             \
        }                                                            \
    } while (0)

#endif

/* [warning] on assertion, do fuck all */
#define WAR(assertion, msg...)                                          \
    do {                                                                \
        if (assertion) {                                                \
            fprintf(stdout, YELLOW_B "[?] %s:%d ", __FILE__, __LINE__); \
            fprintf(stdout, UNSET_B msg);                               \
            fprintf(stdout, CLR "\n");                                  \
        }                                                               \
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

