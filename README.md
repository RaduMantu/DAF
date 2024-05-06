# DAF

A userspace network firewall capable of filtering traffic based on objects
mapped in the address space of the processes that generate them.

## Compilation

Our elapsed time measurement is dependent on the x64 timestamp counter. Hence, we have two requirements:
 1. make sure that the TSC is not influenced by frequency scaling (`cpuid Fn8000_0007:EDX_8` is set)
 2. export the base frequency (in Hz) via the `BASE_FREQ` environment variable before compiling

```
$ BASE_FREQ=2600000000 make -j $(nproc)
```

The base frequency can usually be found in `/sys/devices/system/cpu/cpu0/cpufreq/base_frequency` (in kHz)
or can be determined experimentally if the CPU driver doesn't implement this interface.

Note that the makefile also accepts the `DISABLE_ORDERING=y` argument to enable an optimization.
Details are in the paper; don't use it needlessly.

## Usage

First, create an `iptables` rule to divert packages to our firewall through Netfilter Queue.
Each of the three supported chains (i.e. `INPUT`, `OUTPUT`, `FORWARD`) have a default
queue number assigned. This can be changed via CLI options (check the `--help` info).
Note that the `FORWARD` chain is used solely for payload HMAC validation and doesn't
support rules at the moment (can be easily implemented). In this example, we link `DAF`
to the `OUTPUT` chain to intercept outgoing traffic:

```
$ iptables -I OUTPUT -j NFQUEUE --queue-num 0 --queue-bypass
```

Optionally, traffic to/from the docker bridge can be also routed to
the `INPUT`/`OUTPUT` queues respectively. This is done on the `FORWARD`
chain since the `INPUT` / `OUTPUT` chains that are applicable to a
containerized process reside in a different network namespace.

```
$ iptables -I FORWARD -i docker0 -j NFQUEUE --queue-num 0 --queue-bypass
```

Next, start the firewall. The only argument that _needs_ to be passed is
`-e <ebpf_obj>`. This eBPF object contains trace programs for certain
system calls that can't be monitored by other means (i.e. Netlink).
Here is an invocation example with some optimizations enabled:

```
$ ./bin/app-fw -e bin/syscall_probe.o               \
               -R    `# no address space rescan   ` \
               -S    `# skip namespace switch     ` \
               -b 50 `# max batched verdicts      ` \
               -B 50 `# batch transmission timeout`
```

The firewall rules are managed via the `ctl-fw` companion app. In this example,
we want to DROP traffic generated by `/usr/bin/curl`. To this end, we need to
find its SHA256 sum. We recommend using `ctl-fw` for this, the reason being that
it also outputs an aggregate hash if you specify more than one `-H` parameter.
This is useful when you want to filter traffic based not only on one object, but
all libraries that are to be loaded at runtime. However, under normal
circumstances, `sha256sum` does the job just as well.

```
$ sha256sum /usr/bin/curl
6a3cf1c479f446eb0ef266a2607cd4f6751a655937a7103f7657db6cb6b3f49a  /usr/bin/curl
```

Now knowing the SHA256 sum of `curl`, adding a new rule to DROP outgoing traffic
is straightforward:

```
$ ./bin/ctl-fw                               \
    -A                 `# append           ` \
    -c OUTPUT          `# chain            ` \
    -v DROP            `# verdict          ` \
    -n /proc/$$/ns/net `# network namespace` \
    --sng-hash $(sha256sum /usr/bin/curl | awk '{print $1}')
```

If we send an HTTP request via `curl`, the traffic will be blocked. However, if
you try accessing the same IP from a browser or with `wget`, the request will
pass through.

```
$ curl lwn.net

$ wget lwn.net
$ firefox lwn.net
```

## TODO

Still a few things to finish up (after Easter):
 1. Merge application HMAC match rule option from test system
 2. Code cleanup (also replace verbose license headers with SPDX)
 3. Link paper reference
