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

## License

Our eBPF programs have a section:

```c
char _license[] SEC("license") = "GPL";
```

We have, however, cleared with legal that this does not mean that its
viral nature would propagate to users of these programs as they are
packaged separately and live separately. This is noted here just as
documentation to any future reader that while GPL looks scary in this
case it is *okay*.
