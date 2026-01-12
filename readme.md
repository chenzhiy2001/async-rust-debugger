# async-rust-debugger

## usage

```sh
make env
# to avoid recompiling you can use just-debug
make debug TESTCASE=minimal
(gdb) ardb-gen-whitelist
```
in `temp/poll_functions.txt` you can add sync functions or delete functions you don't want to trace.

then in `gdb` run
```sh
(gdb) ardb-load-whitelist
(gdb) ardb-trace the function you want to start tracing from
(gdb) run
```

