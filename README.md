# linux.io_uring: io_uring forensics for Volatility 3

With io_uring, a Linux process hands its file and network work to the kernel through two rings in shared
memory instead of one syscall per operation. Tools that watch syscalls see little of it, and `lsof` and `sockstat` miss
part of it, because a ring can open files and sockets for itself without any fd. The rings stay in memory. These five
Volatility 3 plugins read them from a memory image and show what the process did:

| Plugin | Answers |
|---|---|
| `linux.io_uring.Rings` | Which processes use io_uring? Also rings that no process has an fd for. |
| `linux.io_uring.Files` | Which files and sockets does a ring hold? `Hidden` = no fd table lists them. |
| `linux.io_uring.Ops` | What did the process do last: open, read, connect, send, with paths, addresses and data? |
| `linux.io_uring.Personalities` | Does a ring still act with credentials the process has dropped (for example root)? |
| `linux.io_uring.Buffers` | What is in the memory the process registered with the ring? |

Special words are in [Terms](#terms).

## Setup
You need Python 3.8 or later and Volatility 3 2.24 or later. The image must be x86-64, and its kernel must have the
io_uring structures of Linux 5.13 or later; Debian's 5.10 works too, because it carries the 5.15 backport
([Kernels tested](#kernels-tested)).

1. **Plugin.** Clone this repository (`git clone https://github.com/miqsoft/volatility3-io_uring && cd volatility3-io_uring`)
   or just download `plugins/linux/io_uring.py`. Copy it into a plugin folder, keeping the `linux/` subfolder
   (`plugins/linux/io_uring.py`). All five plugins are in this one file; there is no helper module.
2. **Symbols.** Put the symbol file (ISF) of the image's kernel, made with dwarf2json or btf2json, into a folder of its
   own. Volatility picks the ISF by the kernel banner, so keep the ISFs of other machines out of it.

## Usage
Run Volatility 3 (`vol`) with the two folders from [Setup](#setup):
```
vol -s SYMBOLS -p plugins -f IMAGE linux.io_uring.Rings
vol -s SYMBOLS -p plugins -f IMAGE linux.io_uring.Ops --pid PID
```
`SYMBOLS` is the folder with the ISF, `plugins` the folder that holds `linux/io_uring.py`, `IMAGE` the memory image.
`Rings` lists every process that uses io_uring; `Ops` shows what one of them did last. `Files`, `Personalities` and
`Buffers` take the same arguments, `--pid PID ...` limits any of them to some processes, and `-vv` shows which memory
read failed.

Example output of `linux.io_uring.Files` (columns trimmed): process 577 holds two files and two sockets in its ring. `Hidden` is `True` when no fd table of any process references them:
```
PID  COMM        Slot  Kind    Path / socket                                               Hidden
577  urp-hidden  0     file    /tmp/urp-hidden-direct-577.txt                              True
577  urp-hidden  1     socket  AF_INET/TCP 127.0.0.1:36070 -> 127.0.0.1:47102 ESTABLISHED  True
577  urp-hidden  2     socket  AF_INET/TCP 127.0.0.1:47102 -> 127.0.0.1:36070 ESTABLISHED  True
577  urp-hidden  3     file    /tmp/urp-hidden-regclose-577.txt                            True
```
Every column is explained in [Plugins](#plugins).

### Which plugin when
| Question | Plugin | Look at |
|---|---|---|
| Which processes use io_uring, with which features? | `Rings` | `Setup flags`, counts of fixed files, buffers and personalities, `Notes` |
| Is there a ring that no process has an fd for? | `Rings` | `Notes`: `NO FD in this process or any other` |
| Is there an SQPOLL thread (submissions without syscalls)? | `Rings` | `SQ thread`, `Notes` |
| Which files and sockets does a ring hold that `lsof` and `sockstat` do not list? | `Files` | `Hidden` = `True`, `Path / socket` |
| What did the process do through the ring: files opened, connections made, data sent or read? | `Ops` | `Op`, `Result`, `Arguments`, newest first |
| Did a process drop privileges but keep a ring that runs with the old credentials? | `Personalities` | `Differs`; the `Personality` column of `Ops` |
| What data sits in the registered buffers (staging for exfiltration, for example)? | `Buffers` | `Preview`, `--dump` |

A ring alone is not suspicious: fio, QEMU and databases use io_uring too. `Notes` marks only the unusual cases.

## Plugins
Each plugin below has the same parts: what it shows, an example (real output from test images, columns trimmed), how to
read it, and its columns. All take `--pid PID ...`. Memory that cannot be read and cells without a value (no SQPOLL
thread, no fd table that holds the file) are `-` in the table and `null` in JSON, never 0.

### `linux.io_uring.Rings`: which processes use io_uring
One row per ring and process, also for a ring that no fd points to.
```
$ vol -s SYMBOLS -p plugins -f IMAGE linux.io_uring.Rings
PID  COMM         Found via                                          Setup flags  Fixed files  Buffers  Personalities  Notes
576  urp-plain    fd 4, tctx (tid 576), mmap                                      0            0        0
577  urp-hidden   fd 4, tctx (tid 577), mmap                                      4            0        0
578  urp-persona  fd 3, tctx (tid 578), mmap                                      0            0        1              personality 1 creds differ from task
579  urp-sqpoll   fd 3, tctx (tid 579), mmap                         SQPOLL       0            0        0              SQPOLL: submissions need no syscalls
580  urp-regring  registered ring 0 (tid 580), tctx (tid 580), mmap               0            0        0              NO FD in this process or any other
582  urp-bufs     fd 3, tctx (tid 582), mmap                                      0            2        0
```

**How to read it.** PID 577 has four fixed files (`Files` shows them). PID 578 keeps credentials that differ from its
own (`Personalities`). PID 579 has a kernel thread that takes its requests (SQPOLL). PID 580 has a ring with no fd at
all. A ring shared by several processes (fork, fd passing) has a row in each.

#### How rings are found
`Found via` lists every place that named the ring:

| `Found via` | Where | Finds |
|---|---|---|
| `fd N` | the process's fd table: a file whose operations are the kernel's `io_uring_fops` | a ring with an fd |
| `registered ring N (tid T)`, `tctx (tid T)` | the thread's `io_uring_task` (`task->io_uring`): the slots of registered ring fds (kernel 5.18 and later), and the table of rings the thread has used | a ring whose fd was registered and then closed, or that never had an fd (`REGISTERED_FD_ONLY`) |
| `mmap` | file-backed memory mappings of a ring file | a ring that a process mapped, with or without an fd |

A ring with no fd gets the note `NO FD in this process or any other`, or `NO FD in this process (fd in PID:FD)` when
another process has one. A ring created with `REGISTERED_FD_ONLY` (kernel 6.5 and later) has no fd and no mapping:
```
$ vol -s SYMBOLS -p plugins -f IMAGE linux.io_uring.Rings
PID  COMM         Found via                                          Notes
91   urp-fdonly   registered ring 0 (tid 91), tctx (tid 91)          NO FD in this process or any other
```

**Columns.**

| Column | Meaning |
|---|---|
| `PID`, `COMM` | the process (thread-group leader) |
| `Ring` | address of the kernel's `io_ring_ctx` |
| `Found via` | where the ring was found (see How rings are found above) |
| `Setup flags` | the `IORING_SETUP_*` flags the ring was created with, empty for none |
| `SQ entries` | size of the submission queue |
| `SQ head`, `SQ tail`, `CQ head`, `CQ tail` | the counters of the submission and completion queues |
| `Fixed files`, `Buffers`, `Personalities` | number of occupied fixed-file slots, registered buffers, registered personalities |
| `SQ thread`, `SQ thread TID` | the SQPOLL kernel thread: its name and its thread id; `-` without SQPOLL |
| `Notes` | `NO FD ...`; `SQPOLL: submissions need no syscalls`; `personality N creds differ from task`; `mixed-size entries: Ops not decoded`; `ring state unreadable` |

### `linux.io_uring.Files`: files and sockets a ring holds
One row per occupied slot of a ring's fixed-file table.

**How to read it.** `Hidden` = `True` means no fd table of any process holds the file, so `lsof` and `sockstat` do not
show it. The example in [Usage](#usage) has four such slots for PID 577; slot 3 is a file whose fd was closed after it
was given to the ring. A file that a process also holds as an fd has `Hidden` = `False` and its `pid:fd`, as fio does:
```
$ vol -s SYMBOLS -p plugins -f IMAGE linux.io_uring.Files
PID  COMM  Slot  Kind  Path / socket      In fd table (pid:fd)  Hidden
828  fio   0     file  /tmp/real/fio.dat  828:7                 False
```

**Columns.**

| Column | Meaning |
|---|---|
| `Slot` | index in the fixed-file table (the number an SQE with `IOSQE_FIXED_FILE` names, or `-> fixed slot N` in `Ops`) |
| `File` | address of the kernel's `struct file` |
| `Kind`, `Path / socket` | `file` with its path, or `socket` with `family/protocol local -> remote STATE` |
| `In fd table (pid:fd)` | the fd tables that reference the same file; `-` if none |
| `Hidden` | `True` if no fd table of any process references the file |

### `linux.io_uring.Ops`: what the process did last
The recent requests of each ring, newest first. The kernel reuses the ring's slots, so only the last ones are left.
```
$ vol -s SYMBOLS -p plugins -f IMAGE linux.io_uring.Ops --pid 578
PID  Age  Op      Fd    Personality  Result  Completion  Arguments
578  0    READ    4     1            678     user_data   4096 B @0x4a9600 'root:!*:20752:0:99999:7:::\ndaemon:*:20752:0:9999'
578  1    OPENAT  -100  1            4       user_data   '/etc/shadow'
```

**How to read it.** Test process 578 dropped to uid 65534, then opened and read `/etc/shadow` as root through
personality 1 (see `Personalities`). `Age` 0 is the newest request, `Fd` -100 a path from the current directory.

**Columns.**

| Column | Meaning |
|---|---|
| `Age` | 0 = consumed last, 1 = the one before, and so on; `-` = pending (in the SQ, not yet consumed by the kernel) |
| `SQ index` | index of the entry in the SQE array |
| `Op` | the opcode (`OPENAT`, `READ`, `CONNECT`, ...); a number for an opcode this plugin does not know |
| `SQE flags` | `IOSQE_*` flags (`FIXED_FILE`, `IO_LINK`, ...), empty for none |
| `Fd` | the fd as a number, -100 = `AT_FDCWD`; with `FIXED_FILE` in `SQE flags` it is a slot of the fixed-file table; `-` for `SOCKET` and `NOP` |
| `User data` | the tag the program gave the request |
| `Personality` | personality id the request runs with, 0 = the task's own credentials |
| `Result` | the completion's result: a byte count, a new fd or a negative errno; `-` if no completion was found or the CQ cannot be read |
| `Completion` | how the request was matched to its completion (see below) |
| `Arguments` | what the entry points to: path, socket address, data preview, buffer index, fixed slot |

#### `Arguments` by opcode
- a path, for `OPENAT`, `OPENAT2`, `STATX`, `UNLINKAT`, `MKDIRAT`, `SETXATTR`, `GETXATTR`, and old and new path for
  `RENAMEAT`, `LINKAT`, `SYMLINKAT`. An empty `STATX` path with `AT_EMPTY_PATH` is shown as `'' (fd N, AT_EMPTY_PATH)`.
  A path of 256 bytes or more is cut off and ends in `...`.
- the socket address, for `CONNECT` and `BIND` (IPv4, IPv6 such as `[::1]:53`, Unix), and family, type and protocol for
  `SOCKET`.
- the buffer address and length with a preview of up to 48 bytes, for `READ`, `WRITE`, `READ_FIXED`, `WRITE_FIXED`,
  `SEND`, `RECV`, `SEND_ZC`. The length is the one in the request (the buffer size for a read), not the result. In the
  preview, unprintable bytes are `.` and trailing zero bytes are left out.
- `buf N`, for `READ_FIXED` and `WRITE_FIXED`; `to ring fd N data 0x...`, for `MSG_RING`.
- `-> fixed slot N` (or `(alloc)`), for `OPENAT`, `OPENAT2`, `SOCKET` and `ACCEPT` that put the new file into a slot;
  `closes fixed slot N`, for a `CLOSE` of a slot.

Operations that point to an iovec or a message header (`READV`, `WRITEV`, `SENDMSG`, `RECVMSG`) and all other opcodes
show only the opcode and the fd.

#### `Completion`
How `Result` was found:

| `Completion` | Meaning |
|---|---|
| `user_data` | matched by `user_data`, which is unique among the entries and the completions in the ring |
| `order` | the program left `user_data` the same in several requests (liburing programs often leave 0); matched by order: request number *s* completed as completion number *s* |
| `ambiguous` | the ring completed more requests than it consumed (multishot, zero-copy), so the order is off; no result |
| `in flight` | the request has not completed yet; no result |
| `not in CQ` | the completion is no longer in the CQ ring (older than its window); no result |
| `not submitted` | the entry is pending |
| `CQ unreadable` | the CQ ring cannot be read |

### `linux.io_uring.Personalities`: as which user requests run
The credentials stored in a ring (`IORING_REGISTER_PERSONALITY`), next to the process's own.
```
$ vol -s SYMBOLS -p plugins -f IMAGE linux.io_uring.Personalities
PID  COMM         Id  UID  EUID  GID  CapEff         Task UID  Task EUID  Task GID  Task CapEff  Differs
578  urp-persona  1   0    0     0    0x1ffffffffff  65534     65534      65534     0x0          True
```

**How to read it.** Root stored its credentials in the ring and then dropped to uid 65534: `Differs` = `True`. A
request that names this personality still runs as root. `Rings` flags it in `Notes`.

**Columns.**

| Column | Meaning |
|---|---|
| `Id` | the personality id an SQE names in its `personality` field |
| `UID`, `EUID`, `GID`, `CapEff` | the stored credentials: uid, effective uid, gid, effective capability mask |
| `Task UID`, `Task EUID`, `Task GID`, `Task CapEff` | the same for the process's own credentials |
| `Differs` | `True` if the stored credentials differ from the process's own |

### `linux.io_uring.Buffers`: data in registered buffers
Memory the process lent to the ring for I/O, with a preview of its contents. `--dump` writes every buffer to a file in
the `-o` directory.
```
$ vol -s SYMBOLS -p plugins -f IMAGE linux.io_uring.Buffers
PID  COMM      Index  User address    Length  Segments  Preview                                          Missing bytes
582  urp-bufs  0      0x7feeff802000  4096    1         URP-BUF0-CANARY registered buffer zero pid=582   0
582  urp-bufs  1      0x7feeff803000  8192    2         URP-BUFS-FILE-CANARY read into fixed buffer 1\n  0
```

**How to read it.** The kernel pins these pages, so their contents stay in the image even when the process's other
pages were swapped out. `Missing bytes` counts what the image does not hold.

**Columns.**

| Column | Meaning |
|---|---|
| `Index` | index of the buffer in the ring's buffer table (`buf N` in `Ops`) |
| `User address`, `Length`, `Segments` | where the buffer is in the process, its length, and the number of pinned page segments |
| `Preview` | the first 48 bytes; unprintable bytes are `.`, trailing zero bytes are left out |
| `Missing bytes` | bytes of the buffer that are not in the image (shown as zeros) |
| `File` | with `--dump`, the file written to the `-o` directory: `io_uring.<pid>.<ring>.buf<N>.dmp`; `-` without it |

### For plugin authors
The four plugins other than `Rings` are subclasses of it. Other plugins can call
`Rings.list_rings(context, kernel_module_name, filter_func)`. It returns the rings, like `PsList.list_tasks`.

## Volatility bugs and how the plugin handles them
The plugin works on the released Volatility 3 2.28.2 thanks to the workarounds below. Each one is local to the plugin
and will be removed as soon as its fix is merged and released in Volatility 3. "Ours" means the issue or pull request
is from the author of this plugin.

| Bug | Upstream | Effect | What the plugin does |
|---|---|---|---|
| SysV shared memory segment 0 crashes the VMA walk | issue [#2082](https://github.com/volatilityfoundation/volatility3/issues/2082), PR [#2083](https://github.com/volatilityfoundation/volatility3/pull/2083) (ours) | `get_vma_iter()` raises on a process with segment 0 attached. fio has one, so a plugin built on it ends on a real image | walks the memory regions without the crashing check |
| `kernel_cap_t.get_capabilities()` fails on kernels before 6.3 | PR [#2017](https://github.com/volatilityfoundation/volatility3/pull/2017) (another author), merged on `develop`, not in 2.28.2 | the ISF of a 6.2 or older kernel names `kernel_cap_t`, and 2.28.2 then expects the 6.3 `u64`; the capabilities of a credential cannot be read through it | reads `cap_effective` itself: the `u64` from 6.3, two `u32` words before |
| `linux.sockstat` shows no IPv6 addresses when Volatility runs on macOS or Windows | PR [#2052](https://github.com/volatilityfoundation/volatility3/pull/2052) (another author), on `develop`, not in 2.28.2 | `Files` shows `None` for the addresses of an IPv6 socket in a fixed-file table | reads the IPv6 addresses itself |

Two behaviours of the framework that the plugin works around, not bugs: the `XArray` helper yields entries without their
index, and the personality id is the index, so the plugin walks the personalities xarray itself. Volatility masks
kernel pointer values to the address width of the layer, so the plugin canonicalizes them before it compares them with
addresses read from the fd tables.

## Tests and validation
The plugins' output is compared with ground truth recorded while the system ran, never with earlier plugin output.
A C probe starts one process per scenario and logs every request, file, credential and
buffer it gives a ring; a checker compares the plugins with that log. The seven scenarios: a plain ring, files and sockets held only by the ring, stored root credentials, SQPOLL, a registered and closed ring fd, a ring
with no fd at all, and registered buffers.

### Kernels tested
- **Run on real images, all checks pass:** Debian 5.10, 6.1 and 6.12; Ubuntu 5.13, 5.15, 5.19, 6.5, 6.8 and 6.17;
  Alpine 6.18. A scenario that needs a newer kernel (registered ring fd: 5.18, no fd at all: 6.5) is skipped on older
  ones.
- **Read from the kernel sources only, not run:** 5.14, 5.16 to 5.18, 6.0, 6.2 to 6.4, 6.6, 6.7, 6.9 to 6.11, 6.13 to
  6.16.

### Also tested
- **Real tools.** Curing, RingReaper and fio on Debian 6.1: the files opened, connects and data sent
  match the C2 logs, and fio's rings, fixed file and buffers match its job settings.
- **Versions.** Volatility 3 2.28.2; the Debian 6.1 probe image also on 2.24.0 and `develop`. Python 3.14, and 3.8
  for the unit tests and six of the images.
- **Unit tests** (`python -m pytest -q tests`, 134 tests): what no image holds. The kernel layouts between the tested
  kernels, queue counters that wrap, matching results to requests, argument decoding per opcode, and damaged or
  unreadable memory. They fail when the plugin is broken on purpose.

## Terms
- **ring**: one io_uring instance (`io_ring_ctx` in the kernel) with its submission and completion queues.
- **SQ / SQE**: submission queue and one entry in it. An SQE is one requested operation.
- **CQE**: one entry in the completion queue. It holds the result of an operation.
- **fixed file**: a file in a ring's fixed-file table. Also called a direct descriptor when opened into a slot.
- **hidden**: a fixed file that no fd table references. `lsof` and `sockstat` do not list it.
- **registered fd**: a ring fd that the process registered with the ring. It can then close the normal fd.
- **personality**: credentials (`struct cred`) registered on a ring. A request can run with them.
- **SQPOLL**: a setup flag. A kernel thread polls the SQ, so the process makes no syscall to submit.
- **ISF**: Volatility 3 symbol file for one kernel. `dwarf2json` or `btf2json` makes it.
- **probe**: our C program. It makes rings and writes the ground truth.
- **image**: a memory dump of a test VM.
- **C2**: command and control. The server that an attacker's tool talks to.

## License
Volatility Software License 1.0, see `LICENSE`. Donated under Volatility Foundation, Inc. Individual
Contributor Licensing Agreement. Author: Michael Külper.
