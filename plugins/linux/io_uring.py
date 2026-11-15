# This file is Copyright 2026 Michael Külper and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
# Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement
#
"""io_uring instances in Linux memory: rings, fixed files, operation history, personalities, buffers.

A process hands I/O to the kernel through two rings in shared memory, so syscall-based monitoring sees little of
it, and some io_uring state lives where the usual plugins do not look:

* direct descriptors (`file_index` on OPENAT/SOCKET/ACCEPT) and registered-then-closed files exist only in the
  ring's fixed-file table: `linux.lsof` and `linux.sockstat` do not list them;
* a ring whose fd was registered (IORING_REGISTER_RING_FDS) and closed, or created with
  IORING_SETUP_REGISTERED_FD_ONLY (6.5+), has no fd at all;
* a registered personality keeps a `struct cred`: operations can run with credentials the task dropped;
* consumed submission queue entries stay in the ring: a short history of operations;
* registered buffers stay pinned and hold the data last read or written through them.

Rings are found per process from its fd table, each thread's `io_uring_task` and its VMAs; the `Found via`
column says where. Needs the io_uring structures of Linux 5.13 or later (also Debian's 5.10 with the 5.15 io_uring
backport); the layout changes of 5.14 to 6.18 are handled. Run on 5.10 (Debian backport), 5.13, 5.15, 5.19, 6.1, 6.5,
6.8, 6.12, 6.17 and 6.18; the kernels in between are read from their sources only.

Code map, top to bottom:

* constants and tables (opcodes, flags, kernel limits), then small helpers (names, text, VMA walk, IPv6 addresses);
* `RingState`, `Sqe`: the queue state and one submission entry, as read; `Ring`: one ring as seen from one process;
* `KernelAccess`: what the three classes below share (kernel objects, bounded counts, process memory, xarray walk);
* `RingFinder`: finds the rings: processes, fd tables, thread contexts, mappings, and who holds a ring file;
* `RingReader`: reads a ring: queue state, fixed files, registered buffers, personalities, SQEs, CQEs and their match;
* `RingDecoder`: describes what a ring points to: files, sockets, and the paths, addresses and data an SQE names;
* `IoUringCore`: the three for one kernel; each `Ring` carries one;
* `Rings` (the rows every plugin starts with, `list_rings`), `Files`, `Ops`, `Personalities`, `Buffers`: the plugins.
"""

import collections
import ipaddress
import itertools
import logging
import struct
from typing import Callable, Dict, Iterator, List, NamedTuple, Optional, Tuple

from volatility3.framework import constants, exceptions, interfaces, objects, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import pslist, sockstat

vollog = logging.getLogger(__name__)

# include/uapi/linux/io_uring.h: enum io_uring_op (append-only, numbers are stable)
OPCODES = (
    "NOP READV WRITEV FSYNC READ_FIXED WRITE_FIXED POLL_ADD POLL_REMOVE SYNC_FILE_RANGE SENDMSG RECVMSG TIMEOUT "
    "TIMEOUT_REMOVE ACCEPT ASYNC_CANCEL LINK_TIMEOUT CONNECT FALLOCATE OPENAT CLOSE FILES_UPDATE STATX READ WRITE "
    "FADVISE MADVISE SEND RECV OPENAT2 EPOLL_CTL SPLICE PROVIDE_BUFFERS REMOVE_BUFFERS TEE SHUTDOWN RENAMEAT "
    "UNLINKAT MKDIRAT SYMLINKAT LINKAT MSG_RING FSETXATTR SETXATTR FGETXATTR GETXATTR SOCKET URING_CMD SEND_ZC "
    "SENDMSG_ZC READ_MULTISHOT WAITID FUTEX_WAIT FUTEX_WAKE FUTEX_WAITV FIXED_FD_INSTALL FTRUNCATE BIND LISTEN "
    "RECV_ZC EPOLL_WAIT READV_FIXED WRITEV_FIXED PIPE"
).split()
# include/uapi/linux/io_uring.h: IORING_SETUP_* (bit numbers) and IOSQE_*
SETUP_FLAGS = (
    "IOPOLL SQPOLL SQ_AFF CQSIZE CLAMP ATTACH_WQ R_DISABLED SUBMIT_ALL COOP_TASKRUN TASKRUN_FLAG SQE128 CQE32 "
    "SINGLE_ISSUER DEFER_TASKRUN NO_MMAP REGISTERED_FD_ONLY NO_SQARRAY HYBRID_IOPOLL CQE_MIXED SQE_MIXED"
).split()
SETUP = {name: 1 << bit for bit, name in enumerate(SETUP_FLAGS)}
# entries of two sizes in one ring (6.18+)
SETUP_MIXED = SETUP["CQE_MIXED"] | SETUP["SQE_MIXED"]
SQE_FLAGS = "FIXED_FILE IO_DRAIN IO_LINK IO_HARDLINK ASYNC BUFFER_SELECT CQE_SKIP_SUCCESS".split()
FILE_INDEX_ALLOC = (
    0xFFFFFFFF  # IORING_FILE_INDEX_ALLOC: the kernel picks the direct descriptor slot
)
# Flag bits in the low bits of `file_ptr` (fs/io_uring.c, io_uring/filetable.h): three in 5.13 to 5.15 (FFS_ASYNC_READ,
# FFS_ASYNC_WRITE, FFS_ISREG), two in 5.16 to 5.18 and 6.1 on (FFS_NOWAIT, FFS_ISREG), three in 5.19 and 6.0 (FFS_SCM
# added). A `struct file` comes from a SLAB_HWCACHE_ALIGN cache (fs/file_table.c), so its address has its low bits
# clear in every case and one mask serves all of them.
FILE_PTR_FLAGS = 0b111
FFS_MASK = ~FILE_PTR_FLAGS
AT_EMPTY_PATH = 0x1000
SOCK_TYPE_MASK = 0xF  # the rest of the type argument is SOCK_NONBLOCK / SOCK_CLOEXEC
AF_UNIX, AF_INET, AF_INET6 = 1, 2, 10
AF_NAMES = {
    AF_UNIX: "AF_UNIX",
    AF_INET: "AF_INET",
    AF_INET6: "AF_INET6",
    16: "AF_NETLINK",
    17: "AF_PACKET",
    40: "AF_VSOCK",
}
SOCK_TYPES = {1: "STREAM", 2: "DGRAM", 3: "RAW", 5: "SEQPACKET"}

# ops whose sqe->addr (and for some off/addr3) point to a path in user memory
PATH_OPS = {
    **dict.fromkeys("OPENAT OPENAT2 STATX UNLINKAT MKDIRAT".split(), ("addr",)),
    **dict.fromkeys("RENAMEAT LINKAT SYMLINKAT".split(), ("addr", "off")),
    **dict.fromkeys(("SETXATTR", "GETXATTR"), ("addr3",)),
}
DATA_OPS = {"READ", "WRITE", "READ_FIXED", "WRITE_FIXED", "SEND", "RECV", "SEND_ZC"}
# ops whose `file_index` is the direct descriptor slot to fill (CLOSE: the slot to close)
DIRECT_OPS = {"OPENAT", "OPENAT2", "SOCKET", "ACCEPT"}
# ops whose `fd` field is not a file descriptor
NO_FD_OPS = {"NOP", "SOCKET"}
ESCAPES = {
    0x0A: "\\n",
    0x0D: "\\r",
    0x09: "\\t",
}  # how `printable` shows newline, return and tab
PATH_READ = 256  # bytes read for a path; a longer one is shown cut off
PREVIEW = 48
SOCKADDR_IN, SOCKADDR_MAX = (
    16,
    128,
)  # sizeof(struct sockaddr_in), most bytes read for a sockaddr

# The SQ and CQ counters are free-running u32 values. The SQ ring header is 64 bytes per entry, or 128 with
# SQE128; the CQ ring 16 per entry, or 32 with CQE32.
SEQ_MASK = 0xFFFFFFFF
SQE_SIZE, SQE128_SIZE = 64, 128
CQE_SIZE, CQE32_SIZE = 16, 32
# struct io_uring_sqe: opcode flags ioprio fd off addr len op_flags user_data buf_index
SQE = struct.Struct("<BBHiQQIIQHHIQQ")
#                                        personality file_index addr3 pad
CQE = struct.Struct("<QiI")  # user_data res flags

# Limits the kernel enforces at setup/registration, used to reject smeared sizes
# (io_uring/io_uring.h IORING_MAX_ENTRIES, IORING_MAX_CQ_ENTRIES; io_uring/rsrc.c IORING_MAX_FIXED_FILES/_REG_BUFFERS)
MAX_SQ_ENTRIES = 32768
MAX_CQ_ENTRIES = 2 * MAX_SQ_ENTRIES
MAX_FIXED_FILES = 1 << 20
MAX_REG_BUFFERS = 1 << 14
MAX_BUFFER = 1 << 30  # a registered buffer is at most 1 GiB
MAX_BVECS = 1 << 18  # i.e. 2**18 4 KiB pages
TABLE_CHUNK = 512  # pointers read at a time from a fixed-file or buffer table
FILE_TABLE_CHUNK = 512  # slots per second-level chunk of the 5.13 and 5.14 fixed-file table (IORING_MAX_FILES_TABLE)
RING_FD_REG_MAX = 16  # IO_RINGFD_REG_MAX: slots of io_uring_task.registered_rings
UBUF_UNUSED = (
    (1 << 64) - 1
)  # `ubuf` of the kernel's placeholder for an empty buffer slot (-1UL: no user address)
# same corruption guard as LinuxUtilities.files_descriptors_for_process
MAX_FDS = 500000
MAX_PERSONALITY_ID = (
    0xFFFF  # xa_alloc_cyclic(..., XA_LIMIT(0, USHRT_MAX)) in io_register_personality
)
# xarray entries up to this are sibling, retry and zero entries, not node pointers
XA_NODE_MIN = 4096
MAX_XA_NODES = 4096  # the 65536 personality ids need about 1100 nodes
XA_NO_PARENT = 64  # above any xa_node.shift

# what the Ops "Completion" column says about how an SQE was matched to its CQE
PENDING = "not submitted"  # in the SQ ring, not yet consumed by the kernel
BY_USER_DATA = "user_data"
BY_ORDER = "order"  # user_data not unique: SQE number s completed as CQE number s
AMBIGUOUS = (
    "ambiguous"  # the ring completed more requests than it consumed: numbering shifted
)
IN_FLIGHT = "in flight"
NOT_IN_CQ = "not in CQ"  # no completion in the CQ ring (older than its window)
CQ_UNREADABLE = "CQ unreadable"


def opname(code: int) -> str:
    """The name of an io_uring opcode, its number as text for one this table does not know."""
    return OPCODES[code] if code < len(OPCODES) else str(code)


def flag_names(value: int, names: List[str]) -> str:
    """`value` as the names of its set bits (bit i is `names[i]`) joined with `|`; bits without a name as one hex
    number; empty if no bit is set."""
    out = [n for i, n in enumerate(names) if value & (1 << i)]
    rest = value & ~((1 << len(names)) - 1)
    if rest:
        out.append(hex(rest))
    return "|".join(out)


def printable(data: bytes) -> str:
    """Text for a table cell: ASCII as it is, newline, return and tab escaped, every other byte as `.`; the
    trailing NUL bytes (padding of a buffer) left out."""
    return "".join(
        ESCAPES.get(b) or (chr(b) if 0x20 <= b < 0x7F else ".")
        for b in data.rstrip(b"\x00")
    )


def attempt(ring: "Ring", what: str, fn: Callable):
    """fn(), or None if kernel memory needed for it is unreadable (logged); callers show None as unreadable."""
    try:
        return fn()
    except exceptions.InvalidAddressException as e:
        vollog.debug("ring %#x: %s unreadable: %s", ring.addr, what, e)
        return None


def personality_ids(
    ring: "Ring", personalities
) -> Iterator[Tuple[int, Optional[tuple], Optional[tuple], Optional[bool]]]:
    """(id, credential ids, the task's credential ids, whether they differ) of each of the ring's personalities;
    ids are None where a cred cannot be read, and so is the comparison then."""
    cred_ids = ring.core.reader.cred_ids
    task_ids = attempt(ring, "task cred", lambda: cred_ids(ring.task.cred))
    for idx, cred in personalities:
        ids = attempt(ring, f"personality {idx}", lambda: cred_ids(cred))
        differs = None if ids is None or task_ids is None else ids != task_ids
        yield idx, ids, task_ids, differs


def unreadable(count: int) -> Tuple:
    """`count` values for the cells of memory that could not be read."""
    return tuple(renderers.UnreadableValue() for _ in range(count))


def not_available(count: int) -> Tuple:
    """`count` values for the cells that do not apply to a row."""
    return tuple(renderers.NotAvailableValue() for _ in range(count))


def shown(value):
    """`value`, or an unreadable cell for None."""
    return renderers.UnreadableValue() if value is None else value


def vma_iter(mm) -> Iterator[interfaces.objects.ObjectInterface]:
    """The VMAs of an `mm_struct`, as `mm.get_vma_iter()` gives them, without its crash: `vm_area_struct.is_valid()`
    raises AttributeError on a file mapping for which `get_inode()` is None (SysV shared memory segment 0, whose
    inode number is 0, as fio or PostgreSQL map it; volatility3#2082, fix proposed in #2083). Such a
    mapping is kept, as `is_valid()` would keep it without that check.

    Args:
        mm: the `mm_struct` of a task

    Returns:
        The valid VMAs
    """
    # _do_get_vma_iter: the walk without the check (no public equivalent in 2.28.2)
    for vma in getattr(mm, "_do_get_vma_iter", mm.get_vma_iter)():
        try:
            if not vma.is_valid():
                continue
        except AttributeError:
            pass
        yield vma


def v6_addresses(sk) -> Tuple[str, str]:
    """The local and the peer address of an AF_INET6 socket, read from `sock_common` (an IPv4-mapped address as plain
    IPv4). vol3 2.28.2 gives None for both on a macOS or Windows host: it compares `skc_family` with the host's
    `AF_INET6`, 30 there and 10 in Linux (volatility3#2052, fixed on develop).

    Args:
        sk: the `sock` of the socket

    Returns:
        (local address, peer address) as text
    """
    common = sk.__sk_common
    packed = (
        struct.pack("<IIII", *addr.in6_u.u6_addr32)
        for addr in (common.skc_v6_rcv_saddr, common.skc_v6_daddr)
    )
    local, peer = (
        str(ip.ipv4_mapped or ip) for ip in map(ipaddress.IPv6Address, packed)
    )
    return local, peer


class RingState(NamedTuple):
    """The SQ/CQ state of one ring (struct io_ring_ctx and its struct io_rings)."""

    flags: int  # IORING_SETUP_*
    sq_entries: int
    cq_entries: int
    sq_head: int
    sq_tail: int
    cq_head: int
    cq_tail: int
    cached_sq_head: int
    cqes: int  # address of the CQE array


class Sqe(NamedTuple):
    """One submission queue entry: the struct io_uring_sqe fields, where it is in the ring, and its completion."""

    opcode: int
    flags: int  # IOSQE_*
    ioprio: int
    fd: int
    off: int
    addr: int
    len: int
    op_flags: int
    user_data: int
    buf_index: int
    personality: int
    file_index: int
    addr3: int
    pad: int
    seq: int  # submission number (position in the SQ, before masking)
    sq_index: int  # index into the SQE array
    age: Optional[int]  # 0 = consumed last; None while pending
    result: Optional[int] = None  # filled in by RingReader.match_results
    completion: str = ""  # how: PENDING, BY_USER_DATA, ...

    @property
    def pending(self) -> bool:
        """Submitted to the SQ but not yet consumed by the kernel."""
        return self.age is None


class Ring:
    """One io_ring_ctx as seen from one process."""

    def __init__(self, core: "IoUringCore", addr: int, ctx, pid: int, comm: str, task):
        self.core = core  # reads and describes the ring
        self.addr = addr
        self.ctx = ctx
        self.pid, self.comm = pid, comm  # thread-group leader (what pslist shows)
        # first thread with an address space and fd table: the leader unless it has exited
        self.task = task
        self.sources: List[str] = []
        self.fds: List[int] = []


class KernelAccess:
    """What the three classes below share: typed kernel objects, bounded counts, process memory and a bounded xarray
    walk. Raises `SymbolError` for a kernel without the io_uring structures this plugin reads."""

    def __init__(self, context: interfaces.context.ContextInterface, kernel_name: str):
        self.context = context
        self.kernel = context.modules[kernel_name]
        self.kernel_name = kernel_name
        self.layer = context.layers[self.kernel.layer_name]
        if not (
            self.kernel.has_symbol("io_uring_fops")
            and self.kernel.has_type("io_file_table")
            and self.kernel.has_type("io_uring_task")
            and self.kernel.has_type("io_ring_ctx")
            and self.kernel.get_type("io_ring_ctx").has_member("personalities")
        ):
            raise exceptions.SymbolError(
                "io_ring_ctx.personalities",
                self.kernel.symbol_table_name,
                "linux.io_uring needs the io_uring structures of Linux 5.13 or later (or Debian's 5.10 with the 5.15 "
                "io_uring backport): io_uring_fops, io_file_table, io_uring_task or io_ring_ctx.personalities missing",
            )
        self.xa = linux.XArray(context, kernel_name)

    @staticmethod
    def is_pointer(template) -> bool:
        """Whether an ISF type template is a pointer (as opposed to a struct, an array or a base type)."""
        object_class = template.vol.get("object_class")
        return isinstance(object_class, type) and issubclass(
            object_class, objects.Pointer
        )

    def obj(self, type_name: str, addr: int):
        """The kernel object of type `type_name` at the (canonical) address `addr`."""
        return self.kernel.object(object_type=type_name, offset=addr, absolute=True)

    def sane(
        self, count: int, limit: int, what: str, power_of_two: bool = False
    ) -> int:
        """`count`, or an InvalidAddressException when it exceeds what the kernel allows (smeared or freed memory),
        or is negative, or zero or not a power of two where the kernel rounds it to one."""
        if (
            count < 0
            or count > limit
            or (power_of_two and (not count or count & (count - 1)))
        ):
            raise exceptions.InvalidAddressException(
                self.layer.name, count, f"{what}: {count} entries"
            )
        return count

    def user_read(self, task, addr: int, size: int) -> Optional[bytes]:
        """Bytes of a user buffer as far as they are paged in, or None."""
        if not size:
            return b""
        name = task.add_process_layer()
        if not name or not addr:
            return None
        try:
            return utility.gather_contiguous_bytes_from_address(
                self.context, self.context.layers[name], addr, size
            )
        except exceptions.InvalidAddressException:
            return None

    def user_string(self, task, addr: int, size: int = PATH_READ) -> Optional[str]:
        """The NUL-terminated string at a user address (`...` after a cut-off one), or None if it is unreadable."""
        data = self.user_read(task, addr, size)
        if data is None:
            return None
        text = data.split(b"\x00", 1)[0].decode("utf-8", "replace")
        return text + "..." if len(data) == size and b"\x00" not in data else text

    def xa_entries(self, head: int) -> Iterator[Tuple[int, int]]:
        """(index, entry) of the pointers an xarray holds, for the xarray whose `xa_head` is `head`.

        Not `XArray.get_entries`: it gives no index (the personality id an SQE names), and a corrupt node can make
        its recursion run through 64 slots per level for as many levels as `shift` says. The walk here needs every
        node to lie below its parent and stops after `MAX_XA_NODES`.

        Args:
            head: the value of `xa_head`

        Returns:
            (index, entry) pairs, by index
        """
        xa = self.xa
        if not head:
            return
        if not xa.node_is_internal(head):
            if not xa.is_node_tagged(head):  # a single entry, at index 0
                yield 0, head
            return
        # nodes to visit: (pointer, index of the first slot, shift of the parent)
        stack = [(xa.untag_node(head), 0, XA_NO_PARENT)]
        visited = 0
        while stack:
            if visited == MAX_XA_NODES:
                vollog.debug(
                    "xarray at %#x: more than %d nodes, stopped", head, visited
                )
                return
            visited += 1
            nodep, base, parent_shift = stack.pop()
            node = xa.nodep_to_node(nodep)
            shift = int(node.shift)
            if shift >= parent_shift:
                continue
            children = []
            for i in range(xa.CHUNK_SIZE):
                slot = int(node.slots[i])
                index = base + (i << shift)
                if not slot:
                    continue
                if not xa.node_is_internal(slot):
                    if not xa.is_node_tagged(slot):
                        yield index, slot
                elif slot > XA_NODE_MIN and shift:
                    children.append((xa.untag_node(slot), index, shift))
            stack.extend(reversed(children))


class RingFinder(KernelAccess):
    """Finds the rings of every process: through its fd tables, thread contexts and mappings."""

    def __init__(self, context: interfaces.context.ContextInterface, kernel_name: str):
        super().__init__(context, kernel_name)
        self.fops = self.kernel.object_from_symbol("io_uring_fops").vol.offset
        # 5.18 and 5.19: `registered_rings` is a pointer to the array, from 6.0 on the array itself
        tctx_type = self.kernel.get_type("io_uring_task")
        self.rings_by_pointer = tctx_type.has_member(
            "registered_rings"
        ) and self.is_pointer(tctx_type.child_template("registered_rings"))
        self._fd_owners: Optional[Dict[int, List[Tuple[int, int]]]] = None
        self._ring_owners: Optional[Dict[int, List[Tuple[int, int]]]] = None

    # ---------- processes and their fds ----------
    def processes(self, filter_func) -> Iterator[Tuple[List, object, int, str]]:
        """([leader and its threads], task to read fds and memory from, pid, comm) per process."""
        for leader in pslist.PsList.list_tasks(
            self.context, self.kernel_name, filter_func
        ):
            try:
                threads = [leader, *leader.get_threads()]
                # an exited leader has no files and no mm any more, its other threads still have
                task = next((t for t in threads if t.files and t.mm), leader)
                pid, comm = int(leader.pid), utility.array_to_string(leader.comm)
            except exceptions.InvalidAddressException as e:
                vollog.debug("task %#x unreadable: %s", leader.vol.offset, e)
                continue
            yield threads, task, pid, comm

    def fd_table(self, task) -> Iterator[Tuple[int, int]]:
        """(fd, struct file address) of a task's fd table.

        Not LinuxUtilities.files_descriptors_for_process: it resolves a path for every fd, which is slow and
        not needed here.
        """
        try:
            files = task.files
            table = files.get_fds() if files else 0
            max_fds = files.get_max_fds() if table else 0
            if not table or max_fds > MAX_FDS:
                return
            fds = utility.array_of_pointers(
                table,
                count=max_fds,
                context=self.context,
                subtype=self.kernel.symbol_table_name + constants.BANG + "file",
            )
            for fd, filp in enumerate(fds):
                if filp:
                    yield fd, self.layer.canonicalize(int(filp))
        except exceptions.InvalidAddressException as e:
            vollog.debug("fd table of task %#x unreadable: %s", task.vol.offset, e)

    @staticmethod
    def distinct_fd_tables(threads: List) -> Iterator:
        """The threads that have an fd table of their own. Threads share one table, except those started without
        CLONE_FILES or that called unshare(CLONE_FILES); a file only such a thread holds is not hidden."""
        seen = set()
        for thread in threads:
            try:
                files = int(thread.files)
            except exceptions.InvalidAddressException:
                continue
            if files and files not in seen:
                seen.add(files)
                yield thread

    def fd_owners(self) -> Dict[int, List[Tuple[int, int]]]:
        """struct file address -> [(pid, fd)] over every process in the image."""
        if self._fd_owners is None:
            self._fd_owners = {}
            for threads, _task, pid, _comm in self.processes(lambda _: False):
                for thread in self.distinct_fd_tables(threads):
                    for fd, filp in self.fd_table(thread):
                        self._fd_owners.setdefault(filp, []).append((pid, fd))
        return self._fd_owners

    def ring_owners(self) -> Dict[int, List[Tuple[int, int]]]:
        """io_ring_ctx address -> [(pid, fd)] of the fds that refer to it, in any process."""
        if self._ring_owners is None:
            self._ring_owners = {}
            for filp, where in self.fd_owners().items():
                ctx = self.ctx_of_file(filp)
                if ctx:
                    self._ring_owners.setdefault(ctx, []).extend(where)
        return self._ring_owners

    def ctx_of_file(self, filp: int) -> Optional[int]:
        """The (canonical) address of the io_ring_ctx behind a struct file, if it is a ring file."""
        try:
            f = self.obj("file", filp)
            # vol3 masks pointer values to the layer's address width: canonicalize to get the kernel address back
            return (
                self.layer.canonicalize(int(f.private_data))
                if int(f.f_op) == self.fops
                else None
            )
        except exceptions.InvalidAddressException:
            return None

    # ---------- ring discovery ----------
    def find_rings(
        self, core: "IoUringCore", filter_func: Callable = lambda _: False
    ) -> Iterator[Ring]:
        """Every ring of every process, once per process, with the places it was found. Each `Ring` carries `core`."""
        for threads, task, pid, comm in self.processes(filter_func):
            rings: Dict[int, Ring] = {}
            for ctx, source, fd in itertools.chain(
                self._from_fds(task), self._from_tctx(threads), self._from_vmas(task)
            ):
                ring = rings.get(ctx)
                if ring is None:
                    ring = rings[ctx] = Ring(
                        core, ctx, self.obj("io_ring_ctx", ctx), pid, comm, task
                    )
                if source not in ring.sources:
                    ring.sources.append(source)
                if fd is not None:
                    ring.fds.append(fd)
            yield from rings.values()

    def _from_fds(self, task) -> Iterator[Tuple[int, str, Optional[int]]]:
        for fd, filp in self.fd_table(task):
            ctx = self.ctx_of_file(filp)
            if ctx:
                yield ctx, f"fd {fd}", fd

    def _from_tctx(self, threads) -> Iterator[Tuple[int, str, None]]:
        """Rings a thread has used (task->io_uring->xa) and rings it registered an fd slot for (5.18+)."""
        for t in threads:
            try:
                if not (t.has_member("io_uring") and t.io_uring):
                    continue
                tid = int(t.pid)
                tctx = t.io_uring.dereference()
                if tctx.has_member("registered_rings"):
                    for i, ctx in self._registered_rings(tctx, tid):
                        yield ctx, f"registered ring {i} (tid {tid})", None
                for _index, node in self.xa_entries(int(tctx.xa.xa_head)):
                    ctx = int(self.obj("io_tctx_node", node).ctx)
                    yield self.layer.canonicalize(ctx), f"tctx (tid {tid})", None
            except exceptions.InvalidAddressException as e:
                vollog.debug(
                    "io_uring_task of task %#x unreadable: %s", t.vol.offset, e
                )

    def _registered_rings(self, tctx, tid: int) -> Iterator[Tuple[int, int]]:
        """(slot, io_ring_ctx address) of the ring files a thread registered (`registered_rings`, 5.18 on). An
        unreadable array gives no rings; the rest of the thread's `io_uring_task` is still read."""
        try:
            if self.rings_by_pointer:
                # 5.18, 5.19: a pointer to a kcalloc'd array of RING_FD_REG_MAX file pointers
                table = self.layer.canonicalize(int(tctx.registered_rings))
                size = 8 * RING_FD_REG_MAX
                raw = self.layer.read(table, size) if table else bytes(size)
                files = struct.unpack(f"<{RING_FD_REG_MAX}Q", raw)
            else:
                # 6.0 on: the array is part of the struct
                files = [int(f) for f in tctx.registered_rings]
        except exceptions.InvalidAddressException as e:
            vollog.debug("registered rings of tid %d unreadable: %s", tid, e)
            return
        for i, filp in enumerate(files):
            ctx = self.ctx_of_file(filp) if filp else None
            if ctx:
                yield i, ctx

    def _from_vmas(self, task) -> Iterator[Tuple[int, str, None]]:
        """Rings mapped into the process (file-backed VMAs of the ring file)."""
        try:
            if not task.mm:
                return
            for vma in vma_iter(task.mm):
                try:
                    ctx = self.ctx_of_file(int(vma.vm_file)) if vma.vm_file else None
                except exceptions.InvalidAddressException:
                    continue
                if ctx:
                    yield ctx, "mmap", None
        except exceptions.InvalidAddressException as e:
            vollog.debug("VMAs of task %#x unreadable: %s", task.vol.offset, e)


class RingReader(KernelAccess):
    """Reads what a ring holds: queue state, fixed files, registered buffers, personalities, SQEs and CQEs."""

    def __init__(self, context: interfaces.context.ContextInterface, kernel_name: str):
        super().__init__(context, kernel_name)
        # io_file_table holds io_rsrc_data + io_rsrc_node pointers from 6.13 on (io_uring/filetable.h)
        self.new_tables = self.kernel.get_type("io_file_table").has_member("data")
        # 5.13 and 5.14: `files` is a table of pointers to chunks of FILE_TABLE_CHUNK slots (`io_fixed_file **`)
        self.two_level_files = not self.new_tables and self.is_pointer(
            self.kernel.get_type("io_file_table").child_template("files").vol.subtype
        )

    # ---------- ring state ----------
    def ring_state(self, ring: Ring) -> RingState:
        """The SQ and CQ state of a ring.

        The sizes are those of `io_ring_ctx`, not those in `io_rings`: the process maps `io_rings` writable and
        the kernel never reads its mask and entry counts again after the setup.

        Raises:
            InvalidAddressException: if a size is not one that the kernel can have set up (smeared or freed ring)
        """
        ctx = ring.ctx
        sq_entries = self.sane(
            int(ctx.sq_entries), MAX_SQ_ENTRIES, "SQ entries", power_of_two=True
        )
        cq_entries = self.sane(
            int(ctx.cq_entries), MAX_CQ_ENTRIES, "CQ entries", power_of_two=True
        )
        rings = ctx.rings.dereference()
        return RingState(
            flags=int(ctx.flags),
            sq_entries=sq_entries,
            cq_entries=cq_entries,
            sq_head=int(rings.sq.head),
            sq_tail=int(rings.sq.tail),
            cq_head=int(rings.cq.head),
            cq_tail=int(rings.cq.tail),
            cached_sq_head=int(ctx.cached_sq_head),
            cqes=rings.cqes.vol.offset,
        )

    @staticmethod
    def sq_thread(ring: Ring, st: RingState) -> Optional[Tuple[int, str]]:
        """(TID, comm) of the SQPOLL kernel thread; None if the ring has none (no SQPOLL, or the thread is gone).

        Raises:
            InvalidAddressException: if the thread's task cannot be read
        """
        ctx = ring.ctx
        if not (st.flags & SETUP["SQPOLL"] and ctx.sq_data):
            return None
        thread = ctx.sq_data.thread
        if not thread:
            return None
        return int(thread.pid), utility.array_to_string(thread.comm)

    def fixed_files(self, ring: Ring) -> Iterator[Tuple[int, Optional[int]]]:
        """(slot, struct file address) for every occupied slot of the fixed-file table.

        The address is None for a slot that cannot be read: the first slot of every unreadable run of the table.
        Raises InvalidAddressException if the table's start is unreadable.
        """
        ctx = ring.ctx
        if self.new_tables:
            nr, table = int(ctx.file_table.data.nr), int(ctx.file_table.data.nodes)
        else:
            nr, table = int(ctx.nr_user_files), int(ctx.file_table.files)
        # the file pointer has flag bits in the low bits
        for slot, ptr in self._rsrc_entries(
            ring,
            nr,
            table,
            MAX_FIXED_FILES,
            "file_ptr",
            "fixed files",
            two_level=self.two_level_files,
        ):
            if ptr is None:
                yield slot, None
            elif ptr & FFS_MASK:
                yield slot, ptr & FFS_MASK

    def buffers(self, ring: Ring) -> Iterator[Tuple[int, Optional[object]]]:
        """(index, io_mapped_ubuf) for every registered buffer (None if the entry cannot be read)."""
        ctx = ring.ctx
        if self.new_tables:
            nr, table, dummy = int(ctx.buf_table.nr), int(ctx.buf_table.nodes), 0
        else:
            nr, table = int(ctx.nr_user_bufs), int(ctx.user_bufs)
            # up to 6.10 the placeholder of an empty slot is allocated per ring; from 6.11 on it is one static
            # object. Volatility masks pointer values, the table entries are raw: compare canonical addresses.
            dummy = (
                self.layer.canonicalize(int(ctx.dummy_ubuf))
                if ctx.has_member("dummy_ubuf")
                else 0
            )
        for i, imu in self._rsrc_entries(
            ring, nr, table, MAX_REG_BUFFERS, "buf", "registered buffers"
        ):
            if imu is None:
                yield i, None
            elif imu != dummy and not self._is_placeholder(imu):
                yield i, self.obj("io_mapped_ubuf", imu)

    def _is_placeholder(self, imu: int) -> bool:
        """Whether the `io_mapped_ubuf` at `imu` is the kernel's placeholder for an empty slot: its `ubuf` is -1UL,
        which no user buffer can have. Needed from 6.11 on, where the placeholder is a static object that no member
        of the ring points to; false if it cannot be read (the buffer is then listed as unreadable)."""
        try:
            return int(self.obj("io_mapped_ubuf", imu).ubuf) == UBUF_UNUSED
        except exceptions.InvalidAddressException:
            return False

    def table_pointers(
        self, table: int, count: int
    ) -> Iterator[Tuple[int, Optional[int]]]:
        """(index, value) of the `count` pointers at `table`, `TABLE_CHUNK` at a time. A chunk that cannot be read
        gives one (index of its first pointer, None) instead of zeros, which would pass for empty slots; the first
        chunk raises InvalidAddressException."""
        for first in range(0, count, TABLE_CHUNK):
            n = min(TABLE_CHUNK, count - first)
            try:
                raw = self.layer.read(table + 8 * first, 8 * n)
            except exceptions.InvalidAddressException:
                if not first:
                    raise
                yield first, None
                continue
            yield from enumerate(struct.unpack(f"<{n}Q", raw), first)

    def two_level_pointers(
        self, table: int, count: int
    ) -> Iterator[Tuple[int, Optional[int]]]:
        """(index, value) of the `count` slots of a 5.13 or 5.14 fixed-file table: `table` holds one pointer per
        chunk of FILE_TABLE_CHUNK slots. An unreadable chunk gives one (index of its first slot, None); an
        unreadable first level raises InvalidAddressException."""
        chunks = -(-count // FILE_TABLE_CHUNK)
        for c, chunk in self.table_pointers(table, chunks):
            first = c * FILE_TABLE_CHUNK
            slots = None
            if chunk:  # None: the first level is unreadable here; 0: the chunk was never allocated
                try:
                    slots = list(
                        self.table_pointers(chunk, min(FILE_TABLE_CHUNK, count - first))
                    )
                except exceptions.InvalidAddressException:
                    pass
            if slots is None:
                yield first, None
                continue
            for i, value in slots:
                yield first + i, value

    def _rsrc_entries(
        self,
        ring: Ring,
        nr: int,
        table: int,
        limit: int,
        member: str,
        what: str,
        two_level: bool = False,
    ) -> Iterator[Tuple[int, Optional[int]]]:
        """(index, pointer) of the non-zero entries of the fixed-file (`member` "file_ptr") or buffer ("buf")
        table, which `what` names in messages. From 6.13 on the table holds io_rsrc_node pointers and the pointer
        is the node's `member` (None if the node cannot be read). `two_level` is the 5.13 and 5.14 fixed-file
        table."""
        if not table:
            return
        pointers = self.two_level_pointers if two_level else self.table_pointers
        for i, entry in pointers(table, self.sane(nr, limit, what)):
            if entry is None:
                yield i, None
            elif entry:
                pointer = self._rsrc_pointer(ring, i, entry, member, what)
                if pointer != 0:
                    yield i, pointer

    def _rsrc_pointer(
        self, ring: Ring, index: int, entry: int, member: str, what: str
    ) -> Optional[int]:
        """The pointer a table entry stands for: the entry itself, or from 6.13 on `member` of its io_rsrc_node."""
        if not self.new_tables:
            return entry
        try:
            return int(getattr(self.obj("io_rsrc_node", entry), member))
        except exceptions.InvalidAddressException as e:
            vollog.debug("ring %#x: %s %d unreadable: %s", ring.addr, what, index, e)
            return None

    @staticmethod
    def buffer_len(imu) -> int:
        """The length of a registered buffer in bytes."""
        if imu.has_member("len"):
            return int(imu.len)
        return int(imu.ubuf_end) - int(imu.ubuf)  # before 6.12

    def buffer_bytes(self, imu, limit: Optional[int] = None) -> Tuple[bytes, int, int]:
        """Contents of a registered buffer from its pinned pages (bio_vecs) up to `limit` bytes, the number of
        missing bytes (pages that the image does not hold, or bio_vecs that cannot be read: read as zeros in the
        data), and the length of the buffer.

        Raises:
            InvalidAddressException: if the length is more than a buffer can have
        """
        length = self.sane(self.buffer_len(imu), MAX_BUFFER, "buffer bytes")
        phys = self.context.layers[self.layer.config["memory_layer"]]
        bv_size = self.kernel.get_type("bio_vec").size
        base = imu.bvec.vol.offset
        want = length if limit is None else min(limit, length)
        out, missing = bytearray(), 0
        for i in range(min(int(imu.nr_bvecs), MAX_BVECS)):
            wanted = want - len(out)
            if wanted <= 0:
                break
            try:
                bv = self.obj("bio_vec", base + i * bv_size)
                size = min(int(bv.bv_len), wanted)
            except exceptions.InvalidAddressException:
                break  # the length of an unreadable bio_vec is not known
            try:
                out += phys.read(
                    bv.bv_page.dereference().to_paddr() + int(bv.bv_offset), size
                )
            except (exceptions.InvalidAddressException, AttributeError):
                missing += size
                out += b"\x00" * size
        missing += want - len(out)
        out += b"\x00" * (want - len(out))
        return bytes(out), missing, length

    def personalities(self, ring: Ring) -> Iterator[Tuple[int, object]]:
        """(id, struct cred) of each registered personality.

        Own walk of the xarray because the framework's XArray yields entries without their index, and the index
        is the personality id an SQE refers to.
        """
        for index, cred in self.xa_entries(int(ring.ctx.personalities.xa_head)):
            if index <= MAX_PERSONALITY_ID:
                yield index, self.obj("cred", cred)

    @staticmethod
    def cred_ids(cred) -> Tuple[int, int, int, int, int]:
        """(uid, euid, gid, egid, effective capabilities). Not kernel_cap_t.get_capabilities(): before 6.3 the ISF
        names the struct kernel_cap_t too, and 2.28.2 then expects the 6.3 u64 (fixed on develop, volatility3#2017)."""
        cap = cred.cap_effective
        if cap.has_member("val"):  # kernel_cap_t is a u64 from 6.3 on
            caps = int(cap.val)
        else:  # u32 cap[2]
            caps = int(cap.cap[0]) | (int(cap.cap[1]) << 32)
        return cred.uid, cred.euid, cred.gid, cred.egid, caps

    # ---------- submission and completion queues ----------
    @staticmethod
    def submission_order(
        head: int, tail: int, entries: int
    ) -> Iterator[Tuple[int, Optional[int]]]:
        """(submission number, age) of the ring's SQ positions, newest first: the entries the kernel has not
        consumed yet (age None), which are `tail - head` of them when that is at most `entries`, then those it
        consumed, age 0 being the last. The counters are u32 and wrap; the history before the wrap is not
        followed, so the `entries` positions after a wrap are fewer.

        Args:
            head: the kernel's consumed count (`cached_sq_head`)
            tail: the process's submitted count (`sq.tail`)
            entries: the size of the SQ ring

        Returns:
            (submission number, age) pairs
        """
        pending = (tail - head) & SEQ_MASK
        if pending <= entries:
            for i in range(pending - 1, -1, -1):
                yield (head + i) & SEQ_MASK, None
        for age in range(min(entries, head)):
            yield head - 1 - age, age

    def sqes(self, ring: Ring, st: RingState) -> Iterator[Sqe]:
        """Submission entries, newest first: pending ones (age None), then consumed ones (age 0 = last submitted)."""
        sqes = int(ring.ctx.sq_sqes)
        if not sqes:
            return
        entries, mask = st.sq_entries, st.sq_entries - 1
        size = SQE128_SIZE if st.flags & SETUP["SQE128"] else SQE_SIZE
        raw = self.layer.read(sqes, size * entries)
        array = None
        if not st.flags & SETUP["NO_SQARRAY"] and int(ring.ctx.sq_array):
            array = struct.unpack(
                f"<{entries}I", self.layer.read(int(ring.ctx.sq_array), 4 * entries)
            )
        seen = set()
        for seq, age in self.submission_order(st.cached_sq_head, st.sq_tail, entries):
            idx = array[seq & mask] if array else seq & mask
            if idx >= entries or idx in seen:
                continue  # an older submission whose SQE slot was reused since
            seen.add(idx)
            if not any(raw[idx * size : (idx + 1) * size]):
                continue  # never used
            yield Sqe(*SQE.unpack_from(raw, idx * size), seq=seq, sq_index=idx, age=age)

    def cqes(self, st: RingState) -> Dict[int, Tuple[int, int, int]]:
        """CQ sequence number -> (user_data, res, cqe flags) for every completion still in the CQ ring."""
        size = CQE32_SIZE if st.flags & SETUP["CQE32"] else CQE_SIZE
        n, mask = st.cq_entries, st.cq_entries - 1
        raw = self.layer.read(st.cqes, size * n)
        return {
            k: CQE.unpack_from(raw, (k & mask) * size)
            for k in range(max(st.cq_tail - n, 0), st.cq_tail)
        }

    @staticmethod
    def match_results(
        st: RingState,
        entries: List[Sqe],
        cqes: Optional[Dict[int, Tuple[int, int, int]]],
    ) -> List[Sqe]:
        """The entries with `result` and `completion` set.

        By user_data when it is unique among the SQEs and CQEs in the rings (liburing apps that tag requests).
        Otherwise (e.g. user_data left 0) by order: SQE number s completed as CQE number s, which holds for
        programs that submit and reap one request at a time. That is only given when the CQE's user_data agrees
        and the ring has not completed more requests than it consumed (multishot or zero-copy ops post extra CQEs
        and shift the numbering: then AMBIGUOUS, without a result). IN_FLIGHT and NOT_IN_CQ have no result either;
        with `cqes` None (the CQ ring cannot be read) the completions are CQ_UNREADABLE.
        """
        if cqes is None:
            return [
                e._replace(completion=PENDING if e.pending else CQ_UNREADABLE)
                for e in entries
            ]
        sq_ud = collections.Counter(e.user_data for e in entries)
        cq_by_ud: Dict[int, List[int]] = {}
        for k, (ud, _res, _fl) in cqes.items():
            cq_by_ud.setdefault(ud, []).append(k)
        out = []
        for e in entries:
            ud, seq = e.user_data, e.seq
            ks = cq_by_ud.get(ud, [])
            if e.pending:
                match = (PENDING, None)
            elif sq_ud[ud] == 1 and len(ks) == 1:
                match = (BY_USER_DATA, cqes[ks[0]][1])
            elif seq in cqes and cqes[seq][0] == ud:
                if st.cq_tail <= st.cached_sq_head:
                    match = (BY_ORDER, cqes[seq][1])
                else:
                    match = (AMBIGUOUS, None)
            elif seq >= st.cq_tail:
                match = (IN_FLIGHT, None)
            else:
                match = (NOT_IN_CQ, None)
            out.append(e._replace(completion=match[0], result=match[1]))
        return out


class RingDecoder(KernelAccess):
    """Says what a ring points to in words: files and sockets, and the paths, addresses and data an SQE names."""

    def __init__(self, context: interfaces.context.ContextInterface, kernel_name: str):
        super().__init__(context, kernel_name)
        self.sock_fops = self.kernel.object_from_symbol("socket_file_ops").vol.offset
        self._sock_handlers: Dict[int, sockstat.SockHandlers] = {}

    def sock_handlers(self, task) -> "sockstat.SockHandlers":
        """The socket handlers for the network namespace of `task`, built once per task (each one walks every
        network device)."""
        key = task.vol.offset
        if key not in self._sock_handlers:
            self._sock_handlers[key] = sockstat.SockHandlers(
                self.context, self.kernel_name, task
            )
        return self._sock_handlers[key]

    def describe_file(self, task, filp: int) -> Tuple[str, object]:
        """(kind, description) of a struct file: socket details for sockets, the path otherwise; the description
        is unreadable if the file cannot be read."""
        f = self.obj("file", filp)
        try:
            is_socket = int(f.f_op) == self.sock_fops
        except exceptions.InvalidAddressException:
            return renderers.UnreadableValue(), renderers.UnreadableValue()
        if is_socket:
            try:
                return "socket", self._describe_socket(task, f)
            except (
                exceptions.InvalidAddressException,
                exceptions.SymbolError,
                AttributeError,
            ) as e:
                vollog.debug("socket file %#x unreadable: %s", filp, e)
                return "socket", renderers.UnreadableValue()
        try:
            return "file", linux.LinuxUtilities.path_for_file(self.context, task, f)
        except (exceptions.InvalidAddressException, AttributeError):
            return "file", renderers.UnreadableValue()

    def _describe_socket(self, task, f) -> str:
        """Family, protocol, both ends and state of the socket behind a struct file."""
        sk = self.obj("socket", int(f.private_data)).sk.dereference()
        child, stat, _flt = self.sock_handlers(task).process_sock(sk)
        src, sport, dst, dport, state = stat
        family, proto = sk.get_family(), child.get_protocol() or ""
        if family == "AF_INET6" and src is None:
            src, dst = v6_addresses(sk)
        return f"{family}/{proto} {src}:{sport} -> {dst}:{dport} {state}"

    @staticmethod
    def parse_sockaddr(data: bytes) -> str:
        """A `struct sockaddr` as text: `ip:port`, `[ipv6]:port`, `unix:path` (`@` for an abstract one), else the
        family name."""
        if len(data) < 2:
            return "<sockaddr unreadable>"
        (family,) = struct.unpack_from("<H", data)
        if family == AF_INET and len(data) >= 8:
            (port,) = struct.unpack_from(">H", data, 2)
            return f"{ipaddress.IPv4Address(data[4:8])}:{port}"
        if family == AF_INET6 and len(data) >= 24:
            (port,) = struct.unpack_from(">H", data, 2)
            ip = ipaddress.IPv6Address(data[8:24])
            return f"[{ip.ipv4_mapped or ip}]:{port}"
        if family == AF_UNIX:
            path = data[2:].split(b"\x00", 1)[0] or (
                b"@" + data[3:].split(b"\x00", 1)[0]
            )
            return f"unix:{path.decode('utf-8', 'replace')}"
        return f"{AF_NAMES.get(family, family)} sockaddr"

    def sockaddr(self, task, addr: int, length: int) -> str:
        """The socket address a CONNECT or BIND SQE names (`length` bytes of it, at least a sockaddr_in)."""
        data = self.user_read(task, addr, min(max(length, SOCKADDR_IN), SOCKADDR_MAX))
        if not data:
            return f"<sockaddr {addr:#x} unreadable>"
        return self.parse_sockaddr(data)

    def describe_sqe(self, task, e: Sqe) -> str:
        """Text for one SQE: decoded path, sockaddr or data preview, buffer index, fixed slot; empty if the opcode has
        none of these."""
        name = opname(e.opcode)
        parts = self._operands(task, name, e)
        if name in ("READ_FIXED", "WRITE_FIXED"):
            parts.append(f"buf {e.buf_index}")
        if e.file_index and name in DIRECT_OPS:
            slot = "(alloc)" if e.file_index == FILE_INDEX_ALLOC else e.file_index - 1
            parts.append(f"-> fixed slot {slot}")
        elif e.file_index and name == "CLOSE":
            parts.append(f"closes fixed slot {e.file_index - 1}")
        return " ".join(parts)

    def _operands(self, task, name: str, e: Sqe) -> List[str]:
        """The decoded memory an SQE points to: paths, a sockaddr, the data of a read or write."""
        if name in PATH_OPS:
            return [self._path(task, name, e, field) for field in PATH_OPS[name]]
        if name in ("CONNECT", "BIND"):
            return [self.sockaddr(task, e.addr, e.off)]
        if name == "SOCKET":
            kind = SOCK_TYPES.get(e.off & SOCK_TYPE_MASK, e.off)
            return [f"{AF_NAMES.get(e.fd, e.fd)} {kind} proto {e.len}"]
        if name in DATA_OPS and e.addr:
            data = self.user_read(task, e.addr, min(e.len, PREVIEW))
            shown_data = "<unreadable>" if data is None else f"'{printable(data)}'"
            return [f"{e.len} B @{e.addr:#x} {shown_data}"]
        if name == "MSG_RING":
            return [f"to ring fd {e.fd} data {e.off:#x}"]
        return []

    def _path(self, task, name: str, e: Sqe, field: str) -> str:
        """The path in SQE field `field`, quoted; a STATX of an empty path with AT_EMPTY_PATH is on `fd` itself."""
        addr = getattr(e, field)
        path = self.user_string(task, addr)
        if path is None:
            return f"<path @{addr:#x} unreadable>"
        if not path and name == "STATX" and e.op_flags & AT_EMPTY_PATH:
            return f"'' (fd {e.fd}, AT_EMPTY_PATH)"
        return repr(path)


class IoUringCore:
    """The three classes for one kernel, as the `Ring`s and the linux.io_uring.* plugins use them."""

    def __init__(self, context: interfaces.context.ContextInterface, kernel_name: str):
        self.finder = RingFinder(context, kernel_name)
        self.reader = RingReader(context, kernel_name)
        self.decoder = RingDecoder(context, kernel_name)

    def find_rings(self, filter_func=lambda _: False) -> Iterator[Ring]:
        """The rings `RingFinder.find_rings` finds, each carrying this object."""
        return self.finder.find_rings(self, filter_func)


class Rings(interfaces.plugins.PluginInterface):
    """Lists io_uring instances per process, where each was found (fd, registered ring, tctx, mmap).

    The other linux.io_uring.* plugins build on this one: each lists one kind of state per ring.
    """

    # utility.gather_contiguous_bytes_from_address is from 2.24.0 (sockstat.SockHandlers needs 2.22.0)
    _required_framework_version = (2, 24, 0)
    _version = (2, 0, 0)

    # every row starts with these; _columns are the plugin's own
    _HEAD = [("PID", int), ("COMM", str), ("Ring", format_hints.Hex)]
    _columns = [
        ("Found via", str),
        ("Setup flags", str),
        ("SQ entries", int),
        ("SQ head", int),
        ("SQ tail", int),
        ("CQ head", int),
        ("CQ tail", int),
        ("Fixed files", int),
        ("Buffers", int),
        ("Personalities", int),
        ("SQ thread", str),
        ("SQ thread TID", int),
        ("Notes", str),
    ]

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        reqs = [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel", architectures=["Intel64"]
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
            requirements.VersionRequirement(
                name="linuxutils", component=linux.LinuxUtilities, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="sockhandlers", component=sockstat.SockHandlers, version=(4, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Only these process IDs",
                optional=True,
            ),
        ]
        if cls is not Rings:  # the plugins that build on Rings
            reqs.append(
                requirements.VersionRequirement(
                    name="rings", component=Rings, version=(2, 0, 0)
                )
            )
        return reqs

    @classmethod
    def list_rings(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        filter_func: Callable = lambda _: False,
    ) -> Iterator[Ring]:
        """Lists the io_uring rings of the processes that `filter_func` does not drop, once per process.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the kernel module on which to operate
            filter_func: A function which takes a process object and returns True if the process should be ignored

        Returns:
            `Ring` objects; each carries an `IoUringCore` (`ring.core`): its `reader` decodes the state of the ring, its
            `decoder` describes what it points to and its `finder` says which process holds it
        """
        return IoUringCore(context, kernel_module_name).find_rings(filter_func)

    def ring_rows(self, ring: Ring) -> Iterator[Tuple]:
        """Rows for one ring, without the head columns. An InvalidAddressException makes the caller emit one
        'unreadable' row instead."""
        reader = ring.core.reader
        st = attempt(ring, "ring state", lambda: reader.ring_state(ring))
        nfixed = attempt(
            ring, "fixed files", lambda: len(list(reader.fixed_files(ring)))
        )
        nbufs = attempt(ring, "buffers", lambda: len(list(reader.buffers(ring))))
        pers = attempt(ring, "personalities", lambda: list(reader.personalities(ring)))
        yield (
            ", ".join(ring.sources),
            *self._state_columns(st),
            shown(nfixed),
            shown(nbufs),
            shown(None if pers is None else len(pers)),
            *self._sq_thread_columns(ring, st),
            "; ".join(self._notes(ring, st, pers)),
        )

    @staticmethod
    def _state_columns(st: Optional[RingState]) -> Tuple:
        """Setup flags, SQ entries, SQ and CQ head and tail; unreadable if the ring state is."""
        if st is None:
            return unreadable(6)
        return (
            flag_names(st.flags, SETUP_FLAGS),
            st.sq_entries,
            st.sq_head,
            st.sq_tail,
            st.cq_head,
            st.cq_tail,
        )

    @staticmethod
    def _sq_thread_columns(ring: Ring, st: Optional[RingState]) -> Tuple:
        """The SQPOLL thread's comm and TID: not available without one, unreadable if its task cannot be read."""
        if st is None:
            return unreadable(2)
        try:
            thread = ring.core.reader.sq_thread(ring, st)
        except exceptions.InvalidAddressException as e:
            vollog.debug("ring %#x: SQPOLL thread unreadable: %s", ring.addr, e)
            return unreadable(2)
        return not_available(2) if thread is None else (thread[1], thread[0])

    @staticmethod
    def _notes(ring: Ring, st: Optional[RingState], pers) -> List[str]:
        """What is unusual about a ring: no fd, SQPOLL, entries of mixed size, personalities that differ."""
        notes = []
        if not ring.fds:
            elsewhere = ring.core.finder.ring_owners().get(ring.addr, [])
            notes.append(
                "NO FD in this process"
                + (
                    f" (fd in {', '.join(f'{p}:{fd}' for p, fd in elsewhere)})"
                    if elsewhere
                    else " or any other"
                )
            )
        if st is None:
            notes.append("ring state unreadable")
        else:
            if st.flags & SETUP["SQPOLL"]:
                notes.append("SQPOLL: submissions need no syscalls")
            if st.flags & SETUP_MIXED:
                notes.append("mixed-size entries: Ops not decoded")
        for idx, _ids, _task_ids, differs in personality_ids(ring, pers or []):
            if differs is None:
                notes.append(f"personality {idx} creds unreadable")
            elif differs:
                notes.append(f"personality {idx} creds differ from task")
        return notes

    def _generator(self):
        """Yields one row per ring and kind of state; an unreadable ring gives one 'unreadable' row."""
        pid_filter = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        for ring in self.list_rings(self.context, self.config["kernel"], pid_filter):
            head = (ring.pid, ring.comm, format_hints.Hex(ring.addr))
            try:
                for row in self.ring_rows(ring):
                    yield 0, head + row
            except exceptions.InvalidAddressException as e:
                vollog.debug("ring %#x unreadable: %s", ring.addr, e)
                yield 0, head + self._unreadable()

    def _unreadable(self, *first) -> tuple:
        """A row of the plugin's own columns: `first`, the rest unreadable."""
        return (*first, *unreadable(len(self._columns) - len(first)))

    def run(self):
        return renderers.TreeGrid(self._HEAD + self._columns, self._generator())


class Files(Rings):
    """Lists the fixed-file table of every ring and flags files that no fd table references (hidden from lsof)."""

    _columns = [
        ("Slot", int),
        ("File", format_hints.Hex),
        ("Kind", str),
        ("Path / socket", str),
        ("In fd table (pid:fd)", str),
        ("Hidden", bool),
    ]

    def ring_rows(self, ring):
        """One row per occupied fixed-file slot, with the fd tables that reference the file; Hidden if none."""
        core = ring.core
        owners = core.finder.fd_owners()
        for slot, filp in core.reader.fixed_files(ring):
            if filp is None:
                yield self._unreadable(slot)
                continue
            kind, desc = core.decoder.describe_file(ring.task, filp)
            where = owners.get(filp, [])
            fds = ", ".join(f"{p}:{fd}" for p, fd in where)
            yield (
                slot,
                format_hints.Hex(filp),
                kind,
                desc,
                fds or renderers.NotAvailableValue(),
                not where,
            )


class Ops(Rings):
    """Recovers recent operations from the submission ring (newest first) with their completions."""

    _columns = [
        ("Age", int),
        ("SQ index", int),
        ("Op", str),
        ("SQE flags", str),
        ("Fd", int),
        ("User data", format_hints.Hex),
        ("Personality", int),
        ("Result", int),
        ("Completion", str),
        ("Arguments", str),
    ]

    def ring_rows(self, ring):
        """One row per SQE, newest first, with its completion and decoded arguments."""
        reader, decoder = ring.core.reader, ring.core.decoder
        st = reader.ring_state(ring)
        # entries of two sizes: the fixed-size decoding would be wrong
        if st.flags & SETUP_MIXED:
            yield not_available(len(self._columns))
            return
        cqes = attempt(ring, "completion queue", lambda: reader.cqes(st))
        for e in reader.match_results(st, list(reader.sqes(ring, st)), cqes):
            name = opname(e.opcode)
            if e.completion == CQ_UNREADABLE:
                result = renderers.UnreadableValue()
            else:
                result = renderers.NotAvailableValue() if e.result is None else e.result
            yield (
                renderers.NotAvailableValue() if e.pending else e.age,
                e.sq_index,
                name,
                flag_names(e.flags, SQE_FLAGS),
                renderers.NotAvailableValue() if name in NO_FD_OPS else e.fd,
                format_hints.Hex(e.user_data),
                e.personality,
                result,
                e.completion,
                decoder.describe_sqe(ring.task, e),
            )


class Personalities(Rings):
    """Lists credentials registered on rings (IORING_REGISTER_PERSONALITY) next to the task's own."""

    _columns = [
        ("Id", int),
        ("UID", int),
        ("EUID", int),
        ("GID", int),
        ("CapEff", format_hints.Hex),
        ("Task UID", int),
        ("Task EUID", int),
        ("Task GID", int),
        ("Task CapEff", format_hints.Hex),
        ("Differs", bool),
    ]

    def ring_rows(self, ring):
        """One row per registered personality, with the task's own credentials next to it."""

        def cols(ids):  # uid, euid, gid, capabilities
            if ids is None:
                return unreadable(4)
            return ids[0], ids[1], ids[2], format_hints.Hex(ids[4])

        personalities = ring.core.reader.personalities(ring)
        for idx, ids, task_ids, differs in personality_ids(ring, personalities):
            yield idx, *cols(ids), *cols(task_ids), shown(differs)


class Buffers(Rings):
    """Lists registered buffers with a preview of their contents (read from the pinned pages)."""

    _columns = [
        ("Index", int),
        ("User address", format_hints.Hex),
        ("Length", int),
        ("Segments", int),
        ("Preview", str),
        ("Missing bytes", int),
        ("File", str),
    ]

    @classmethod
    def get_requirements(cls):
        return super().get_requirements() + [
            requirements.BooleanRequirement(
                name="dump",
                description="Write each buffer to a file",
                default=False,
                optional=True,
            ),
        ]

    def ring_rows(self, ring):
        """One row per registered buffer with a preview; with --dump, also writes the full contents to a file."""
        reader, dump = ring.core.reader, self.config.get("dump")
        for idx, imu in reader.buffers(ring):
            found = imu is not None and attempt(
                ring,
                f"buffer {idx}",
                lambda: (
                    reader.buffer_bytes(imu, None if dump else PREVIEW),
                    format_hints.Hex(int(imu.ubuf)),
                    int(imu.nr_bvecs),
                ),
            )
            if not found:
                yield self._unreadable(idx)
                continue
            (data, missing, length), address, segments = found
            fname = renderers.NotAvailableValue()
            if dump:
                fname = f"io_uring.{ring.pid}.{ring.addr:#x}.buf{idx}.dmp"
                with self.open(fname) as fh:
                    fh.write(data)
            yield (
                idx,
                address,
                length,
                segments,
                printable(data[:PREVIEW]),
                missing,
                fname,
            )
