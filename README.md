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