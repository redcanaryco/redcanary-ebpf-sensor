# redcanary-ebpf-sensor

This project consists of a variety of eBPF applications aimed at gathering events
of interest for [Red Canary's Cloud Workload Protection](https://redcanary.com/products/cloud-workload-protection/) 
product.

These applications do not use [BCC](https://github.com/iovisor/bcc) to build. The 
main objective of this design is to have a compile once, run everywhere application.