## How to build 
 Building bpf prgram requires availability of ebpf-for-windows toolchain and clang.exe added to PATH. 
 Assumng ebpf for windows is checked out at `C:\git\ebpf-for-windows`, we can run following commands to build the program:

clang -g -target bpf -O2 -Werror -IC:\git\ebpf-for-windows\include -c .\tcp_connect.c -o tcp_connect.o

c:\git\ebpf-for-windows\x64\Debug\Convert-BpfToNative.ps1 -FileName tcp_connect -IncludeDir C:\git\ebpf-for-windows\include -Platform x64 -Packages C:\git\ebpf-for-windows\packages -Configuration Release -KernelMode $True -Verbose