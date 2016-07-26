This python file using [pyvmi][1] to walk through the process list from the
memory using `/dev/mem`. [LibVMI][2] doesn't really support the introspection of
`/dev/mem` out of the box, although, it does support introspection of memory
snapshots. So, to make it work with `/dev/mem` I applied a *very* dirty hack and
patched the LibVMI's source with a hardcoded value of the size. Since,
`/dev/mem`'s size comes out to be zero.

```
diff --git a/libvmi/driver/file/file.c b/libvmi/driver/file/file.c
index 90830b9..05d0c8e 100644
--- a/libvmi/driver/file/file.c
+++ b/libvmi/driver/file/file.c
@@ -225,8 +225,12 @@ file_get_memsize(
         errprint("Failed to stat file.\n");
         goto error_exit;
     }
-    *allocated_ram_size = s.st_size;
-    *max_physical_address = s.st_size;
+       /*
+        * XXX: Harcoding the size of the memory here as the file descriptor
+        * to /dev/mem would have the size of 0 bytes.
+        */
+    *allocated_ram_size = 1073733632;
+    *max_physical_address = 1073733632;
     ret = VMI_SUCCESS;

 error_exit:
@@ -306,7 +310,9 @@ file_test(
         goto error_exit;
     }
     if (!s.st_size) {
-        goto error_exit;
+               errprint("The file size zero! Please check if it is correct.\n");
+               errprint("Setting the file size to a hardcoded value of :1073733632 \n");
+               s.st_size = 1073733632;
     }
     ret = VMI_SUCCESS;

```

The value of `1073733632` is the size of my memory in bytes. What I did was that
I took a memory snapshot using `dd if=/dev/mem of=mem` and used the size of mem.

After that, just use the `linux_offset_finder` to find offsets of the current
kernel and put that into `/etc/libvmi.conf` which would look something like
this:

```
mem {
    ostype = "Linux";
    sysmap = "/boot/System.map-4.7.0-rc7";
    linux_name = 0x590;
    linux_tasks = 0x2e0;
    linux_mm = 0x330;
    linux_pid = 0x3e0;
    linux_pgd = 0x40;
}
```
_Note_: These values are going to differ for you, this is just an
example. Please don't copy the values from here.

After that, you can just try out LibVMI on your live memory!

This python script compares the state of processes from the memory to entries in
debugfs. I made a linux kernel patch exports the process parameters to debugfs
on every fork. It also deletes the processes on `exit`. The code for that is
available [here][3] for sometime. It is an experimental setup and is gauranteed
to change in next few days.

[1]: https://github.com/libvmi/libvmi
[2]: https://github.com/libvmi/libvmi/tree/master/tools/pyvmi
[3]: https://github.com/maxking/linux/tree/dev/
