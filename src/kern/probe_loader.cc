#include <signal.h>
#include <sys/resource.h>   /* setrlimit */
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "util.h"


static int bml = 0; /* break main loop */

static void sigint_handler(int unused)
{
    bml = 1;
}


int main(int argc, char *argv[])
{
    sig_t              prv_sh;
    struct rlimit      r = {RLIM_INFINITY, RLIM_INFINITY};
    struct bpf_object  *bobj;
    struct bpf_program *bprog;
    struct bpf_link    *blink;
    int                ans;

    /* sanity check */
    if (argc != 2)
        return -1;

    /* set gracious behaviour for Ctrl^C signal */
    prv_sh = signal(SIGINT, &sigint_handler);
    DIE(prv_sh == SIG_ERR, "unable to set new SIGINT handler (%d)", errno);
    INFO("replaced SIGINT handler");

    /* set resource limit (for eBPF maps -- future) */
    ans = setrlimit(RLIMIT_MEMLOCK, &r);
    DIE(ans == -1, "unable to set resource limits");
    INFO("set new resource limits");
    
    /* open eBPF object file */
    bobj = bpf_object__open_file(argv[1], NULL);
    DIE(libbpf_get_error(bobj), "unable to open eBPF object");
    INFO("opened eBPF object file");

    /* load eBPF object */
    ans = bpf_object__load(bobj);
    GOTO(ans, clean_file, "unable to load eBPF object");
    INFO("loaded eBPF object file (passed verification)");

    /* load first program from eBPF object (also the only one) */
    bprog = bpf_program__next(NULL, bobj);
    GOTO(!bprog, clean_file, "unable to fetch program from eBPF object");
    INFO("fetched first program from loaded eBPF object");

    /* attach eBPF program to tracepoint */
    blink = bpf_program__attach(bprog);
    GOTO(!blink, clean_file, "unable to attach program to eBPF tracepoint");
    INFO("attached eBPF program to its corresponding tracepoint");

    /* main loop */
    while (!bml) {
        continue;
    }

clean_link:
    bpf_link__destroy(blink);
    INFO("attached eBPF program was destroyed");

clean_file:
    bpf_object__close(bobj);
    INFO("loaded eBPF object file was closed");

    return 0;
}
