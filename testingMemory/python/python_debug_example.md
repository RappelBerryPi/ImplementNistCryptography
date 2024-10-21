# python is easy to debug

```bash
$ py -m pdb .\example_program.py
> C:\...\example_program.py(1)<module>()
-> from cryptography.hazmat.primitives.ciphers import algorithms, modes
(Pdb) n
> C:\...\example_program.py(2)<module>()
-> import base64
(Pdb) n
> C:\...\example_program.py(3)<module>()
-> import os
(Pdb) n
> C:\...\example_program.py(5)<module>()
-> key = None
(Pdb) n
> C:\...\example_program.py(6)<module>()
-> with open('../key.txt') as key_file:
(Pdb) n
> C:\...\example_program.py(7)<module>()
-> key = base64.b64decode(key_file.readline())
(Pdb) n
> C:\...\example_program.py(6)<module>()
-> with open('../key.txt') as key_file:
(Pdb) n
> C:\...\example_program.py(9)<module>()
-> aes = algorithms.AES(key)
(Pdb) print(key)
b"\x1f\xdbv.`\xb5Jk\xed\xca\x17\x90'\x86c\xa6R\xfb\xa5?\x02\x94q\xf9\xee\xac\x91G\xea[\x1a\xe9"
(Pdb)
```

## example two

```bash
$ py .\example_program_debug.py
> C:\...\example_program_debug.py(8)<module>()
-> with open('../key.txt') as key_file:
(Pdb) print(key)
b"\x1f\xdbv.`\xb5Jk\xed\xca\x17\x90'\x86c\xa6R\xfb\xa5?\x02\x94q\xf9\xee\xac\x91G\xea[\x1a\xe9"
(Pdb)
```

## example three

in window 1

```bash
$ py example_program_long_run_attach_debugger.py
simulating long running process
```

in window 2

```bash
$ ps -aux | grep python3
----      1206  0.0  0.0  17360 10580 pts/0    S+   23:39   0:00 python3 example_program_long_run_attach_debugger.py
----      1207  0.0  0.0   8168   724 pts/1    S+   23:42   0:00 grep --color=auto python3

$ gdb python 1206
GNU gdb (Ubuntu 9.2-0ubuntu1~20.04.2) 9.2
Copyright (C) 2020 Free Software Foundation, Inc.
...
...
26      ../sysdeps/unix/sysv/linux/read.c: No such file or directory.
(gdb) bt
#0  0x00007f083eb511f2 in __GI___libc_read (fd=0, buf=0x23b3c30, nbytes=1024) at ../sysdeps/unix/sysv/linux/read.c:26
#1  0x00007f083ead3b9f in _IO_new_file_underflow (fp=0x7f083ec2f980 <_IO_2_1_stdin_>) at libioP.h:948
...
#20 0x000000000067d831 in run_eval_code_obj (co=0x7f083e3f13a0,
    globals={'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <SourceFileLoader(name='__main__', path='example_program_long_run_attach_debugger.py') at remote 0x7f083e5154c0>, '__spec__': None, '__annotations__': {}, '__builtins__': <module at remote 0x7f083e4ee0e0>, '__file__': 'example_program_long_run_attach_debugger.py', '__cached__': None, 'algorithms': <module at remote 0x7f083e35bd10>, 'modes': <module at remote 0x7f083e2a1360>, 'base64': <module at remote 0x7f083e1ffcc0>, 'os': <module at remote 0x7f083e49a310>, 'key': b"\x1f\xdbv.`\xb5Jk\xed\xca\x17\x90'\x86c\xa6R\xfb\xa5?\x02\x94q\xf9\xee\xac\x91G\xea[\x1a\xe9", 'key_file': <_io.TextIOWrapper at remote 0x7f083e2b9790>, 'aes': <AES(key=b"\x1f\xdbv.`\xb5Jk\xed\xca\x17\x90'\x86c\xa6R\xfb\xa5?\x02\x94q\xf9\xee\xac\x91G\xea[\x1a\xe9") at remote 0x7f083e3f33d0>, 'mode': <GCM(_initialization_vector=b"\xc8\xd3\x05\x98\x8a\xd8\xf3\xd6k?\n\xb8\x07'\xea\xb9", _tag=None, _min_tag_length=16) at remote 0x7f083e1f2970>},
    locals={'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <SourceFileLoader(name='__main__', path='example_program_long_run_attach_debugger.py') at remote 0x7f083e5154c0>, '__spec__': None, '__annotations__': {}, '__builtins__': <module at remote 0x7f083e4ee0e0>, '__file__': 'example_program_long_run_attach_debugger.py', '__cached__': None, 'algorithms': <module at remote 0x7f083e35bd10>, 'modes': <module at remote 0x7f083e2a1360>, 'base64': <module at remote 0x7f083e1ffcc0>, 'os': <module at remote 0x7f083e49a310>, 'key': b"\x1f\xdbv.`\xb5Jk\xed\xca\x17\x90'\x86c\xa6R\xfb\xa5?\x02\x94q\xf9\xee\xac\x91G\xea[\x1a\xe9", 'key_file': <_io.TextIOWrapper at remote 0x7f083e2b9790>, 'aes': <AES(key=b"\x1f\xdbv.`\xb5Jk\xed\xca\x17\x90'\x86c\xa6R\xfb\xa5?\x02\x94q\xf9\xee\xac\x91G\xea[\x1a\xe9") at remote 0x7f083e3f33d0>, 'mode': <GCM(_initialization_vector=b"\xc8\xd3\x05\x98\x8a\xd8\xf3\xd6k?\n\xb8\x07'\xea\xb9", _tag=None, _min_tag_length=16) at remote 0x7f083e1f2970>}) at ../Python/pythonrun.c:1166
...
...
#29 0x00007f083ea67083 in __libc_start_main (main=0x4dba00 <main>, argc=2, argv=0x7fffae68d288, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffae68d278)
    at ../csu/libc-start.c:308
#30 0x00000000005eb5ee in _start () at ../Objects/longobject.c:1170
(gdb) quit
A debugging session is active.

        Inferior 1 [process 1206] will be detached.

Quit anyway? (y or n) y
Detaching from program: /usr/bin/python3.8, process 1206
[Inferior 1 (process 1206) detached]
$
```

note that above, the key is revealed in both 'key' and 'aes' variables


more examples of what can be gathered through this type of debugging can be found
https://fedoraproject.org/wiki/Features/EasierPythonDebugging


## running the program as root causes something else to happen

running as root with the python process makes the process non-debuggable by another user.
however, there's a workaround to his by setting ptace_scope to 0 or by setting setcap cap_sys_ptrace=eip for gdb
https://github.com/microsoft/MIEngine/wiki/Troubleshoot-attaching-to-processes-using-GDB