# redcanary-ebpf-sensor

This project consists of a variety of eBPF applications aimed at gathering events
of interest for [Red Canary's Cloud Workload Protection](https://redcanary.com/products/cloud-workload-protection/)
product.

These applications do not use [BCC](https://github.com/iovisor/bcc) to build. The
main objective of this design is to have a compile once, run everywhere application.

To build this project run
`docker-compose run  --rm ebpf make all`

A vscode cpp properties files has been included. Make sure to update the include path with the path
on your local system where the kernel header files are located

## Gotchas and Patterns

### Dummy Telemetry Event

At the beginning of the programs we often have code that looks like:

```c
telemetry_event_t sev = {0};
```

We then proceed to send `&sev` to our functions and set the proper values there. This is done for two reasons:

1. We want to save stack space, so by creating a single dummy event at
   the top we can remind ourselves that this is the only event we ever
   want to have at a time and it is meant to be reused.

2. The eBPF verifier does not like uninitialized padding. When
   initializing a padded struct in C, not all of the space occupied by
   the struct necessarily gets initialized as padding may exist
   between fields, or empty space unused by some union members. The
   eBPF verifier does not like this so to guarantee nothing is
   unitialized we need to zero out all of the space for the event
   struct. For more information see [this
   issue](https://github.com/iovisor/bcc/issues/2623).

### Per CPU structures

Be careful when using PERCPU structures (such as
`BPF_MAP_TYPE_PERFCPU_ARRAY`). While an eBPF program is not
preemptable, syscalls are. This means that a kprobe for a syscall may
happen in one CPU but its kretprobe will happen in a different
CPU. This means that passing data using per cpu structures accross
programs will not always work in multicore systems. Note, however,
that tail calling is *NOT* preemptable, so it is okay to pass
information using per cpu structures through tail calls.

### Kprobe and Kretprobe synchronization

Since syscalls may start and finish in different CPUs (they are
preemptable), we need to be send extra data to synchronize them in
user space. To do this, we send a a `TE_ENTER_DONE` event as the very
last event produced by a kprobe. Note that since programs may tail
call into other programs we need to follow that tail call through and
send it as the very last event in the final tail call. We also rely on
the `TE_RETCODE` event being the last event in a `kretprobe` so no
extra signaling event is done for them. If this changes in the future
(e.g., due to tail calling) we'll need to add synchronization events
there too.

## Validate Instruction Count

Due to older kernel limitations (< 5.2) the instruction limit for our
ebpf programs is 4096. This was changed in Kernel 5.2+ to be 1 million
but we cannot rely on that at this time. To verify that we aren't
going over the limit, after modifying an ebpf program run it through
`llvm-objdump` and check its instruction count:

```bash
llvm-objdump -d <PATH_TO_COMPILED_FILE> -j <SPECIFIC_SECTION_TO_ANALYZE> | less
```

You may ommit the `-j <SPECIFIC_SECTION_TO_ANALYZE>` if you want to
check all the sections at the same time.

eBPF programs can branch (but not jump back!) so make sure to check
that none of the branches go over the 4096 instructions limit.

# Licensing

Please note, these programs are mostly licensed under GPL, which is
required to leverage BPF features critical for gathering security
telemetry.

```c
char _license[] SEC("license") = "GPL";
```

If you bundle these programs with your own code (for example, by using
`include_bytes!()` in Rust), that extends GPL to your code base.  If
you wish to use your own code with its own license alongside these
programs, you'll need to build, manage, and distribute them
separately.
