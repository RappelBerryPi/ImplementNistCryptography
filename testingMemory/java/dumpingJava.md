# easy to dump java and get the plaintext

First run a program (all below is done on windows)

```bash
$ java Program

$
```

Then run jps to get the PID of program and then run jmap to dump it into a dump file and then search through it for the
key

```bash
$ jps
33124 org.eclipse.equinox.launcher_1.6.900.v20240613-2009.jar
22504 DssLauncher
35196 Jps
30304 Program
```

Now we can run jmap to dump all the memory

```bash
$ jmap -dump:all,format=b,file=a.dmp 30304
Dumping heap to a.dmp ...
Heap dump file created [5202658 bytes in 0.009 secs]
```

Then we can look through this.

If the task is started as admin or a different user then we get an error

```bash
$ jmap -dump:all,format=b,file=a.dmp 30304
Exception in thread "main" java.io.IOException: Access is denied
        at jdk.attach/sun.tools.attach.VirtualMachineImpl.openProcess(Native Method)
        at jdk.attach/sun.tools.attach.VirtualMachineImpl.<init>(VirtualMachineImpl.java:56)
        at jdk.attach/sun.tools.attach.AttachProviderImpl.attachVirtualMachine(AttachProviderImpl.java:69)
        at jdk.attach/com.sun.tools.attach.VirtualMachine.attach(VirtualMachine.java:207)
        at jdk.jcmd/sun.tools.jmap.JMap.executeCommandForPid(JMap.java:128)
        at jdk.jcmd/sun.tools.jmap.JMap.dump(JMap.java:248)
        at jdk.jcmd/sun.tools.jmap.JMap.main(JMap.java:114)
```