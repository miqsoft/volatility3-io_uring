"""Unit tests for linux.io_uring: the decoding of the ring structures on the paths no sample image reaches (other
kernel layouts, ring wraparound, corrupt memory, unreadable pages). Small fakes stand in for the kernel; no images.
A test that guards a fixed defect says so in its docstring."""

import ast
import contextlib
import struct
from types import SimpleNamespace

import pytest
from volatility3.framework import exceptions, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import io_uring, pslist, sockstat

SQES, ARRAY, CQES, TABLE = 0x10000, 0x20000, 0x30000, 0x40000
KERNEL = 0xFFFF888012345000


class Memory:
    """A fake layer: byte regions at addresses; reading anything outside them raises like a missing page."""

    name = "kernel"
    config = {"memory_layer": "phys"}

    def __init__(self, **kwargs):
        self.regions = {}

    def put(self, addr, data):
        self.regions[addr] = bytes(data)

    def read(self, addr, size, pad=False):
        for base, data in self.regions.items():
            if base <= addr and addr + size <= base + len(data):
                return data[addr - base : addr - base + size]
        if pad:  # as the framework does: what is not mapped reads as zeros
            return bytes(size)
        raise exceptions.InvalidAddressException(self.name, addr, "unmapped")

    @staticmethod
    def canonicalize(addr):
        return addr | (0xFFFF << 48) if addr & (1 << 47) else addr


class UserMemory:
    """Process memory for `KernelAccess.user_read`: the bytes at an address up to the end of their region."""

    def __init__(self, regions):
        self.regions = regions  # address -> bytes

    def __call__(self, task, addr, size):
        for base, data in self.regions.items():
            if base <= addr < base + len(data):
                return data[addr - base : addr - base + size]
        return None


def make_core(cls=io_uring.RingReader, **attrs):
    """A `cls` (one of the classes on `KernelAccess`) that was not set up from a symbol table: its layer and
    helpers are fakes."""
    core = object.__new__(cls)
    core.layer = Memory()
    core.context = SimpleNamespace(layers={"phys": Memory()})
    core.kernel = SimpleNamespace(
        symbol_table_name="k", get_type=lambda name: SimpleNamespace(size=16)
    )
    core.kernel_name = "kernel"
    core.new_tables = False
    core.two_level_files = core.rings_by_pointer = False
    core.fops, core.sock_fops = 0xFFFFFFFF82000000, 0xFFFFFFFF82001000
    core._fd_owners = core._ring_owners = None
    core._sock_handlers = {}
    core.__dict__.update(attrs)
    return core


def make_ring(reader=None, **ctx):
    """A `Ring` of fake parts: `ctx` are the fields of its io_ring_ctx;  gives."""
    core = SimpleNamespace(reader=reader or make_core())
    task = SimpleNamespace(
        cred="task-cred",
        vol=SimpleNamespace(offset=0x77),
        add_process_layer=lambda: "p",
    )
    return SimpleNamespace(
        core=core,
        addr=0xFFFF888001000000,
        ctx=SimpleNamespace(**ctx),
        pid=7,
        comm="probe",
        task=task,
        sources=["fd 3"],
        fds=[3],
    )


def make_state(**kw):
    values = dict(
        flags=0,
        sq_entries=4,
        cq_entries=8,
        sq_head=0,
        sq_tail=0,
        cq_head=0,
        cq_tail=0,
        cached_sq_head=0,
        cqes=CQES,
    )
    values.update(kw)
    return io_uring.RingState(**values)


def sqe_bytes(
    op="NOP", flags=0, fd=0, off=0, addr=0, len=0, op_flags=0, user_data=0, **kw
):
    """One 64-byte SQE as the kernel's struct io_uring_sqe lays it out."""
    return io_uring.SQE.pack(
        io_uring.OPCODES.index(op),
        flags,
        0,
        fd,
        off,
        addr,
        len,
        op_flags,
        user_data,
        kw.get("buf_index", 0),
        kw.get("personality", 0),
        kw.get("file_index", 0),
        kw.get("addr3", 0),
        0,
    )


def make_sqe(op="NOP", seq=0, age=0, **kw):
    """A decoded `Sqe`, as `RingReader.sqes` gives it."""
    return io_uring.Sqe(
        *io_uring.SQE.unpack(sqe_bytes(op, **kw)), seq=seq, sq_index=0, age=age
    )


def component(requirement):
    """The class a VersionRequirement names, and the version it asks for (no public accessor)."""
    return requirement._component, requirement._version


def populate(plugin):
    """The rows of a plugin after the TreeGrid has checked each value against its column type."""
    rows = []
    grid = renderers.TreeGrid(plugin._HEAD + plugin._columns, plugin._generator())
    grid.populate(lambda node, acc: rows.append(tuple(node.values)) or acc)
    return rows


def make_plugin(cls, rings, **config):
    """A plugin that is not set up by the framework: its rings and configuration are given."""

    class Fake(cls):
        context = None

        @classmethod
        def list_rings(cls_, context, kernel_module_name, filter_func=None):
            return iter(rings)

        def open(self, name):
            return self.sink.open(name)

    Fake.config = {"kernel": "kernel", **config}
    plugin = object.__new__(Fake)
    plugin.sink = Sink()
    return plugin


class Sink:
    """What `plugin.open` writes: file name -> bytes."""

    def __init__(self):
        self.files = {}

    @contextlib.contextmanager
    def open(self, name):
        buf = bytearray()
        yield SimpleNamespace(write=buf.extend)
        self.files[name] = bytes(buf)


@pytest.fixture(autouse=True)
def plain_strings(monkeypatch):
    """The fakes carry text where the kernel has char arrays."""
    monkeypatch.setattr(io_uring.utility, "array_to_string", lambda text: text)


# --- declarations ---------------------------------------------------------------------------------------


def test_requirements_are_the_plugins_own_components_and_nothing_from_the_shell_plugins():
    reqs = {r.name: r for r in io_uring.Rings.get_requirements()}
    assert set(reqs) == {"kernel", "pslist", "linuxutils", "sockhandlers", "pid"}
    assert component(reqs["pslist"]) == (pslist.PsList, (4, 0, 0))
    assert component(reqs["sockhandlers"]) == (sockstat.SockHandlers, (4, 0, 0))
    assert component(reqs["linuxutils"]) == (linux.LinuxUtilities, (2, 0, 0))
    source = open(io_uring.__file__, encoding="utf-8").read()
    assert "shell_common" not in source


def test_plugins_on_rings_require_rings_at_its_current_version():
    for plugin in (
        io_uring.Files,
        io_uring.Ops,
        io_uring.Personalities,
        io_uring.Buffers,
    ):
        reqs = {r.name: r for r in plugin.get_requirements()}
        assert component(reqs["rings"]) == (io_uring.Rings, io_uring.Rings._version)
    assert "rings" not in {r.name for r in io_uring.Rings.get_requirements()}
    assert "dump" in {r.name for r in io_uring.Buffers.get_requirements()}


def test_declared_versions_are_met_and_the_framework_minimum_covers_them():
    for req in io_uring.Rings.get_requirements():
        if isinstance(req, requirements.VersionRequirement):
            component_class, wanted = component(req)
            assert requirements.VersionRequirement.matches_required(
                wanted, component_class._version
            )
            assert (
                io_uring.Rings._required_framework_version
                >= component_class._required_framework_version
            )


def test_the_framework_minimum_is_the_one_the_calls_need():
    """Defect: the minimum was 2.22.0 (SockHandlers) although `utility.gather_contiguous_bytes_from_address`, which
    reads user memory, came with 2.24.0; the plugins failed with AttributeError on 2.22 and 2.23."""
    assert io_uring.Rings._required_framework_version >= (2, 24, 0)
    assert hasattr(io_uring.utility, "gather_contiguous_bytes_from_address")


def test_every_plugin_declares_its_columns_once():
    for plugin in (
        io_uring.Rings,
        io_uring.Files,
        io_uring.Ops,
        io_uring.Personalities,
        io_uring.Buffers,
    ):
        names = [name for name, _type in plugin._columns]
        assert len(names) == len(set(names)), plugin


def test_the_module_is_python38_source():
    """No `X | Y` or builtin generics in annotations, no match statement or newer string and int methods: ast.parse
    with `feature_version` catches the syntax, the rest is looked for in the tree."""
    source = open(io_uring.__file__, encoding="utf-8").read()
    tree = ast.parse(source, feature_version=(3, 8))
    annotations = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = node.args
            for arg in [*args.args, *args.kwonlyargs, args.vararg, args.kwarg]:
                annotations.append(arg and arg.annotation)
            annotations.append(node.returns)
        elif isinstance(node, ast.AnnAssign):
            annotations.append(node.annotation)
    bad = []
    for annotation in filter(None, annotations):
        for node in ast.walk(annotation):
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
                bad.append(node.lineno)
            if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
                if node.value.id in ("list", "dict", "tuple", "set", "type"):
                    bad.append(node.lineno)
    newer = {"removeprefix", "removesuffix", "bit_count"}
    bad += [n.lineno for n in ast.walk(tree) if getattr(n, "attr", None) in newer]
    assert not bad, bad


def test_a_kernel_without_the_io_uring_structures_stops_with_one_message():
    kernel = SimpleNamespace(
        layer_name="layer", symbol_table_name="k", has_symbol=lambda name: False
    )
    context = SimpleNamespace(modules={"kernel": kernel}, layers={"layer": Memory()})
    with pytest.raises(exceptions.SymbolError, match="5.13"):
        io_uring.IoUringCore(context, "kernel")


# --- small helpers ---------------------------------------------------------------------------------------


def test_opname_knows_the_table_and_shows_a_newer_number():
    assert io_uring.opname(0) == "NOP"
    assert io_uring.opname(18) == "OPENAT"
    assert io_uring.opname(62) == "PIPE"
    assert io_uring.opname(63) == "63"
    assert len(io_uring.OPCODES) == 63


def test_flag_names_lists_bits_and_keeps_unknown_ones():
    assert io_uring.flag_names(0, io_uring.SETUP_FLAGS) == ""
    assert io_uring.flag_names(0b10, io_uring.SETUP_FLAGS) == "SQPOLL"
    named = io_uring.flag_names((1 << 14) | (1 << 15), io_uring.SETUP_FLAGS)
    assert named == "NO_MMAP|REGISTERED_FD_ONLY"
    assert io_uring.flag_names(1 << 25, io_uring.SETUP_FLAGS) == hex(1 << 25)
    assert (
        io_uring.flag_names(0b1000001, io_uring.SQE_FLAGS)
        == "FIXED_FILE|CQE_SKIP_SUCCESS"
    )


def test_setup_flag_bits_match_the_uapi_header():
    assert io_uring.SETUP["SQPOLL"] == 1 << 1
    assert io_uring.SETUP["SQE128"] == 1 << 10
    assert io_uring.SETUP["CQE32"] == 1 << 11
    assert io_uring.SETUP["NO_MMAP"] == 1 << 14
    assert io_uring.SETUP["NO_SQARRAY"] == 1 << 16
    assert io_uring.SETUP_MIXED == (1 << 18) | (1 << 19)


def test_printable_escapes_whitespace_and_hides_other_bytes():
    assert io_uring.printable(b"a\tb\r\nc") == "a\\tb\\r\\nc"
    assert io_uring.printable("é\x01\x7f".encode()) == "...."
    assert io_uring.printable(b"") == ""


def test_printable_cuts_off_the_padding_but_not_at_the_first_nul():
    """Defect: the text stopped at the first NUL byte, so a buffer holding `ss`, a NUL and an older command's
    remains (RingReaper's receive buffer) or any binary request showed only its first bytes."""
    assert io_uring.printable(b"ss\x00\x00/etc/passwd\x00\x00\x00") == "ss../etc/passwd"
    assert io_uring.printable(b"\x00\x00ab\x00") == "..ab"
    assert io_uring.printable(b"\x00" * 8) == ""


def test_not_available_and_unreadable_cells():
    assert all(
        isinstance(v, renderers.NotAvailableValue) for v in io_uring.not_available(3)
    )
    assert len(io_uring.unreadable(2)) == 2
    assert isinstance(io_uring.shown(None), renderers.UnreadableValue)
    assert io_uring.shown(0) == 0


# --- vma_iter and v6_addresses (the helpers that used to come from shell_common) -------------------------------


def test_vma_iter_keeps_a_mapping_whose_validity_check_crashes():
    """Defect (vol3 2.28.2): `get_vma_iter()` raised AttributeError on a file mapping with no inode, which stopped
    every process that maps SysV shared memory segment 0 (fio, PostgreSQL)."""

    def vma(valid):
        def is_valid():
            if valid is None:
                raise AttributeError("'NoneType' object has no attribute 'i_size'")
            return valid

        return SimpleNamespace(is_valid=is_valid)

    keep, crash, drop = vma(True), vma(None), vma(False)
    mm = SimpleNamespace(
        _do_get_vma_iter=lambda: iter([keep, drop, crash]),
        get_vma_iter=lambda: pytest.fail("the checked walk must not be used"),
    )
    assert list(io_uring.vma_iter(mm)) == [keep, crash]


def test_vma_iter_falls_back_to_the_framework_walk():
    only = SimpleNamespace(is_valid=lambda: True)
    mm = SimpleNamespace(get_vma_iter=lambda: iter([only]))
    assert list(io_uring.vma_iter(mm)) == [only]


def words(address: bytes):
    return SimpleNamespace(
        in6_u=SimpleNamespace(u6_addr32=struct.unpack("<4I", address))
    )


def v6_socket(local: bytes, peer: bytes):
    common = SimpleNamespace(skc_v6_rcv_saddr=words(local), skc_v6_daddr=words(peer))
    return SimpleNamespace(__sk_common=common)


def test_v6_addresses_plain_loopback_and_mapped():
    loopback = bytes(15) + b"\x01"
    mapped = bytes(10) + b"\xff\xff\x7f\x00\x00\x01"
    documentation = bytes.fromhex("20010db8000000000000000000000042")
    assert io_uring.v6_addresses(v6_socket(loopback, documentation)) == (
        "::1",
        "2001:db8::42",
    )
    assert io_uring.v6_addresses(v6_socket(mapped, bytes(16))) == ("127.0.0.1", "::")


# --- user memory ------------------------------------------------------------------------------------------


class FlatLayer:
    """A process layer that is not a translation layer: reads fail outside `data`."""

    def __init__(self, data):
        self.data, self.maximum_address = data, 1 << 20

    def read(self, addr, size):
        if addr + size > len(self.data):
            raise exceptions.InvalidAddressException("p", addr, "end")
        return self.data[addr : addr + size]


def user_core(data=b"", has_process=True, cls=io_uring.KernelAccess):
    core = make_core(cls, context=SimpleNamespace(layers={"p": FlatLayer(data)}))
    task = SimpleNamespace(add_process_layer=lambda: "p" if has_process else None)
    return core, task


def test_user_read_a_zero_length_buffer_is_empty_not_unreadable():
    """Defect: a SEND or WRITE of length 0 was shown as `<unreadable>`: the framework raises for a count of 0."""
    core, task = user_core(b"x" * 8)
    assert core.user_read(task, 0x100, 0) == b""
    assert core.user_read(task, 0x100, 4) is None  # beyond the layer: unreadable


def test_user_read_without_an_address_space_or_address_is_none():
    core, task = user_core(b"abcd", has_process=False)
    assert core.user_read(task, 1, 2) is None
    core, task = user_core(b"abcd")
    assert core.user_read(task, 0, 2) is None
    assert core.user_read(task, 1, 2) == b"bc"


def test_user_string_stops_at_nul_and_marks_a_cut_off_path():
    """Defect: a path longer than the 256 bytes that are read was shown cut off with nothing to say so."""
    core, task = user_core(b"/etc/shadow\x00junk" + bytes(300))
    assert core.user_string(task, 1) == "etc/shadow"
    core, task = user_core(b"x/" + b"a" * 400)
    assert core.user_string(task, 1) == "/" + "a" * 255 + "..."
    core, task = user_core(b"x" + b"a" * 256 + b"\x00")
    assert core.user_string(task, 1, 257) == "a" * 256


# --- socket addresses and the decoded SQEs ----------------------------------------------------------------------


def sockaddr_in(ip, port):
    return (
        struct.pack("<H", 2)
        + struct.pack(">H", port)
        + bytes(map(int, ip.split(".")))
        + bytes(8)
    )


def sockaddr_in6(ip, port):
    packed = bytes.fromhex(ip)
    return (
        struct.pack("<H", 10) + struct.pack(">H", port) + bytes(4) + packed + bytes(4)
    )


def test_parse_sockaddr_v4_v6_unix_and_others():
    assert (
        io_uring.RingDecoder.parse_sockaddr(sockaddr_in("127.0.0.1", 8888))
        == "127.0.0.1:8888"
    )
    loop = sockaddr_in6("00000000000000000000000000000001", 443)
    assert io_uring.RingDecoder.parse_sockaddr(loop) == "[::1]:443"
    mapped = sockaddr_in6("00000000000000000000ffffc0a80001", 80)
    assert io_uring.RingDecoder.parse_sockaddr(mapped) == "[192.168.0.1]:80"
    path = struct.pack("<H", 1) + b"/run/x.sock\x00" + bytes(40)
    assert io_uring.RingDecoder.parse_sockaddr(path) == "unix:/run/x.sock"
    abstract = struct.pack("<H", 1) + b"\x00name\x00" + bytes(40)
    assert io_uring.RingDecoder.parse_sockaddr(abstract) == "unix:@name"
    netlink = struct.pack("<H", 16) + bytes(14)
    assert io_uring.RingDecoder.parse_sockaddr(netlink) == "AF_NETLINK sockaddr"
    assert io_uring.RingDecoder.parse_sockaddr(struct.pack("<H", 99)) == "99 sockaddr"


def test_parse_sockaddr_too_short_for_its_family_is_not_guessed():
    assert io_uring.RingDecoder.parse_sockaddr(b"\x02") == "<sockaddr unreadable>"
    assert (
        io_uring.RingDecoder.parse_sockaddr(sockaddr_in("1.2.3.4", 5)[:6])
        == "AF_INET sockaddr"
    )
    assert (
        io_uring.RingDecoder.parse_sockaddr(sockaddr_in6("00" * 16, 5)[:20])
        == "AF_INET6 sockaddr"
    )


def test_the_connect_sockaddr_read_covers_a_sockaddr_in6_and_stops_at_128_bytes():
    core, task = make_core(io_uring.RingDecoder), None
    sizes = []

    def user_read(task, addr, size):
        sizes.append(size)
        return sockaddr_in6("00" * 15 + "01", 22)[:size]

    core.user_read = user_read
    assert core.sockaddr(task, 0x5000, 28) == "[::1]:22"
    core.sockaddr(task, 0x5000, 0)
    core.sockaddr(task, 0x5000, 4096)
    assert sizes == [28, 16, 128]
    core.user_read = lambda *args: None
    assert core.sockaddr(task, 0x5000, 16) == "<sockaddr 0x5000 unreadable>"


def describe(sqe, memory=None):
    core = make_core(io_uring.RingDecoder)
    core.user_read = UserMemory(memory or {})
    return core.describe_sqe(None, sqe)


def test_openat_shows_the_path_and_the_direct_descriptor_slot():
    sqe = make_sqe("OPENAT", fd=-100, addr=0xA1000, file_index=3)
    assert describe(sqe, {0xA1000: b"/tmp/x\x00"}) == "'/tmp/x' -> fixed slot 2"
    alloc = make_sqe("OPENAT2", addr=0xA1000, file_index=io_uring.FILE_INDEX_ALLOC)
    assert describe(alloc, {0xA1000: b"/tmp/x\x00"}) == "'/tmp/x' -> fixed slot (alloc)"
    assert (
        describe(make_sqe("OPENAT", addr=0xA1000), {0xA1000: b"/tmp/x\x00"})
        == "'/tmp/x'"
    )


def test_an_unreadable_path_names_its_address():
    assert describe(make_sqe("UNLINKAT", addr=0xB000)) == "<path @0xb000 unreadable>"


def test_statx_of_an_empty_path_with_at_empty_path_is_on_the_fd_itself():
    """Defect: any op with an empty path was labelled `AT_EMPTY_PATH`, flag or not, STATX or not."""
    memory = {0xA1000: b"\x00"}
    flagged = make_sqe("STATX", fd=11, addr=0xA1000, op_flags=io_uring.AT_EMPTY_PATH)
    assert describe(flagged, memory) == "'' (fd 11, AT_EMPTY_PATH)"
    assert describe(make_sqe("STATX", fd=11, addr=0xA1000), memory) == "''"
    assert (
        describe(make_sqe("OPENAT", fd=11, addr=0xA1000, op_flags=0x1000), memory)
        == "''"
    )


def test_two_path_ops_show_both_and_xattr_ops_read_addr3():
    rename = make_sqe("RENAMEAT", addr=0xA1000, off=0xA2000)
    assert describe(rename, {0xA1000: b"old\x00", 0xA2000: b"new\x00"}) == "'old' 'new'"
    xattr = make_sqe("SETXATTR", addr=0xA1000, addr3=0xA2000)
    assert (
        describe(xattr, {0xA1000: b"user.k\x00", 0xA2000: b"/etc/f\x00"}) == "'/etc/f'"
    )


def test_connect_and_bind_decode_the_sockaddr_and_socket_decodes_its_arguments():
    v4 = make_sqe("CONNECT", addr=0xA1000, off=16)
    assert describe(v4, {0xA1000: sockaddr_in("10.0.0.7", 4443)}) == "10.0.0.7:4443"
    v6 = make_sqe("BIND", addr=0xA1000, off=28)
    assert describe(v6, {0xA1000: sockaddr_in6("00" * 15 + "01", 53)}) == "[::1]:53"
    # the type argument carries SOCK_NONBLOCK|SOCK_CLOEXEC next to SOCK_STREAM
    sock = make_sqe("SOCKET", fd=2, off=1 | 0o4000 | 0o2000000, len=6)
    assert describe(sock) == "AF_INET STREAM proto 6"
    assert describe(make_sqe("SOCKET", fd=99, off=77, len=0)) == "99 77 proto 0"


def test_send_and_read_show_length_address_and_the_start_of_the_data():
    sqe = make_sqe("SEND", addr=0xA1000, len=29)
    text = describe(sqe, {0xA1000: b"PAYLOAD pid=1\x00" + bytes(40)})
    assert text == "29 B @0xa1000 'PAYLOAD pid=1'"
    assert (
        describe(make_sqe("RECV", addr=0xA1000, len=8)) == "8 B @0xa1000 <unreadable>"
    )
    assert (
        describe(make_sqe("READ", addr=0, len=8)) == ""
    )  # a provided buffer: nothing to read
    # only the first PREVIEW bytes are read
    seen = []
    core = make_core(
        io_uring.RingDecoder,
        user_read=lambda task, addr, size: seen.append(size) or bytes(size),
    )
    core.describe_sqe(None, make_sqe("WRITE", addr=0xA1000, len=4096))
    assert seen == [io_uring.PREVIEW]


def test_a_zero_length_send_shows_an_empty_payload():
    """Defect: SEND with len 0 was shown as `<unreadable>`."""
    core, task = user_core(b"x" * 8, cls=io_uring.RingDecoder)
    sqe = make_sqe("SEND", addr=0x100, len=0)
    assert core.describe_sqe(task, sqe) == "0 B @0x100 ''"


def test_fixed_buffer_ops_name_the_buffer_and_msg_ring_the_target():
    fixed = make_sqe("READ_FIXED", addr=0xA1000, len=4, buf_index=1)
    assert describe(fixed, {0xA1000: b"data"}) == "4 B @0xa1000 'data' buf 1"
    assert (
        describe(make_sqe("MSG_RING", fd=5, off=0xCAFE)) == "to ring fd 5 data 0xcafe"
    )


def test_close_of_a_direct_descriptor_names_the_slot():
    """Defect: CLOSE of a direct descriptor showed `Fd 0` and nothing else, as if it closed fd 0."""
    assert describe(make_sqe("CLOSE", file_index=5)) == "closes fixed slot 4"
    assert describe(make_sqe("CLOSE", fd=9)) == ""


def test_ops_without_decoded_arguments_have_an_empty_text():
    assert describe(make_sqe("NOP")) == ""
    assert describe(make_sqe("TIMEOUT", addr=0x1000)) == ""
    unknown = io_uring.Sqe(
        *io_uring.SQE.unpack(sqe_bytes()), seq=0, sq_index=0, age=0
    )._replace(opcode=200)
    assert make_core(io_uring.RingDecoder).describe_sqe(None, unknown) == ""


# --- ring state ----------------------------------------------------------------------------------------------


def state_ring(sq_entries=4, cq_entries=8, **header):
    rings = SimpleNamespace(
        sq=SimpleNamespace(head=3, tail=5),
        cq=SimpleNamespace(head=2, tail=6),
        cqes=SimpleNamespace(vol=SimpleNamespace(offset=CQES)),
        sq_ring_mask=0xDEAD,
        cq_ring_mask=0xBEEF,
        cq_ring_entries=3,
        **header,
    )
    return make_ring(
        flags=io_uring.SETUP["SQE128"],
        sq_entries=sq_entries,
        cq_entries=cq_entries,
        cached_sq_head=4,
        rings=SimpleNamespace(dereference=lambda: rings),
    )


def test_ring_state_reads_the_sizes_from_the_context_not_the_shared_header():
    """Defect: the SQ mask and the CQ size came from `io_rings`, which the process maps writable; a ring with a
    rewritten header (here mask 0xdead, 3 CQ entries) decoded the wrong slots or none."""
    ring = state_ring()
    st = ring.core.reader.ring_state(ring)
    assert (st.sq_entries, st.cq_entries) == (4, 8)
    assert (st.sq_head, st.sq_tail, st.cq_head, st.cq_tail) == (3, 5, 2, 6)
    assert (st.cached_sq_head, st.cqes, st.flags) == (4, CQES, io_uring.SETUP["SQE128"])


@pytest.mark.parametrize(
    "sq,cq",
    [(0, 8), (3, 8), (65536, 8), (4, 0), (4, 12), (4, 131072)],
)
def test_ring_state_rejects_sizes_the_kernel_cannot_have_set(sq, cq):
    """Defect: a smeared or freed ring with a zero, odd or huge size was shown with those numbers as if it were
    a ring (and sized the reads that follow)."""
    ring = state_ring(sq, cq)
    with pytest.raises(exceptions.InvalidAddressException):
        ring.core.reader.ring_state(ring)


def test_the_largest_rings_the_kernel_allows_are_accepted():
    ring = state_ring(io_uring.MAX_SQ_ENTRIES, io_uring.MAX_CQ_ENTRIES)
    st = ring.core.reader.ring_state(ring)
    assert st.sq_entries == 32768 and st.cq_entries == 65536


def sq_thread_ring(sq_data, flags=io_uring.SETUP["SQPOLL"]):
    return make_ring(sq_data=sq_data), make_state(flags=flags)


def test_the_sqpoll_thread_is_found_or_absent_or_unreadable():
    thread = SimpleNamespace(pid=94, comm="iou-sqp-89")
    ring, st = sq_thread_ring(SimpleNamespace(thread=thread))
    assert io_uring.RingReader.sq_thread(ring, st) == (94, "iou-sqp-89")
    ring, st = sq_thread_ring(0)  # sq_data freed after the thread exited
    assert io_uring.RingReader.sq_thread(ring, st) is None
    ring, st = sq_thread_ring(SimpleNamespace(thread=0))
    assert io_uring.RingReader.sq_thread(ring, st) is None
    ring, st = sq_thread_ring(SimpleNamespace(thread=thread), flags=0)  # no SQPOLL
    assert io_uring.RingReader.sq_thread(ring, st) is None

    class Gone:
        @property
        def thread(self):
            raise exceptions.InvalidAddressException("kernel", 1, "gone")

    ring, st = sq_thread_ring(Gone())
    with pytest.raises(exceptions.InvalidAddressException):
        io_uring.RingReader.sq_thread(ring, st)


# --- the submission queue ----------------------------------------------------------------------------------


def test_submission_order_fresh_ring_pending_first_then_consumed():
    order = list(io_uring.RingReader.submission_order(head=3, tail=5, entries=8))
    assert order == [(4, None), (3, None), (2, 0), (1, 1), (0, 2)]


def test_submission_order_goes_back_at_most_one_ring():
    order = list(io_uring.RingReader.submission_order(head=100, tail=100, entries=4))
    assert order == [(99, 0), (98, 1), (97, 2), (96, 3)]


def test_submission_order_ignores_a_tail_that_cannot_be_right():
    """The tail is written by the process: more pending entries than the ring holds, or a tail behind the head,
    is not believed."""
    ahead = list(io_uring.RingReader.submission_order(head=2, tail=2 + 5, entries=4))
    assert [seq for seq, age in ahead if age is None] == []
    behind = list(io_uring.RingReader.submission_order(head=10, tail=2, entries=4))
    assert [seq for seq, age in behind if age is None] == []


def test_submission_order_follows_the_u32_counters_across_the_wrap():
    """Defect: with the tail wrapped past 2**32 and the head not yet, `tail - head` was negative and the pending
    entries disappeared."""
    order = list(
        io_uring.RingReader.submission_order(head=0xFFFFFFFE, tail=1, entries=4)
    )
    assert order[:3] == [(0, None), (0xFFFFFFFF, None), (0xFFFFFFFE, None)]
    assert order[3] == (0xFFFFFFFD, 0)


def sq_core(entries, slots, array=None, size=64):
    """A core whose layer holds an SQE array (slot -> bytes) and optionally an sq_array."""
    core = make_core()
    raw = bytearray(size * entries)
    for slot, data in slots.items():
        raw[slot * size : slot * size + len(data)] = data
    core.layer.put(SQES, raw)
    if array is not None:
        core.layer.put(ARRAY, struct.pack(f"<{entries}I", *array))
    return core


def sq_ring(core, array=True):
    return make_ring(core, sq_sqes=SQES, sq_array=ARRAY if array else 0)


def fetch(core, ring, **state):
    st = make_state(**state)
    return [(e.seq, e.sq_index, e.age, e.user_data) for e in core.sqes(ring, st)]


def ud(n):
    return sqe_bytes("NOP", user_data=n)


def test_sqes_without_an_sq_array_use_the_masked_sequence_number():
    """Six submissions into four slots: slots 0 and 1 hold the newest two, the older two are gone."""
    slots = {0: ud(4), 1: ud(5), 2: ud(2), 3: ud(3)}
    core = sq_core(4, slots)
    got = fetch(core, sq_ring(core, array=False), cached_sq_head=6, sq_tail=6)
    assert got == [(5, 1, 0, 5), (4, 0, 1, 4), (3, 3, 2, 3), (2, 2, 3, 2)]


def test_sqes_with_a_no_sqarray_ring_ignore_the_array_pointer():
    core = sq_core(4, {0: ud(1)}, array=[3, 3, 3, 3])
    ring = sq_ring(core)
    flags = io_uring.SETUP["NO_SQARRAY"]
    assert fetch(core, ring, flags=flags, cached_sq_head=1, sq_tail=1) == [(0, 0, 0, 1)]


def test_sqes_through_an_sq_array_follow_the_indirection():
    slots = {0: ud(10), 2: ud(20), 3: ud(30)}
    core = sq_core(4, slots, array=[2, 3, 0, 1])
    got = fetch(core, sq_ring(core), cached_sq_head=3, sq_tail=3)
    assert got == [(2, 0, 0, 10), (1, 3, 1, 30), (0, 2, 2, 20)]


def test_sqes_through_an_sq_array_skip_a_slot_that_was_reused_and_a_bad_index():
    core = sq_core(
        4, {0: ud(99)}, array=[0, 0, 0, 7]
    )  # every old submission used SQE 0; entry 3 says 7
    got = fetch(core, sq_ring(core), cached_sq_head=4, sq_tail=4)
    assert got == [
        (2, 0, 1, 99)
    ]  # seq 3 -> index 7 is out of range; the older ones were overwritten by seq 2


def test_sqes_list_pending_entries_before_consumed_ones():
    core = sq_core(4, {0: ud(1), 1: ud(2), 2: ud(3), 3: ud(4)})
    got = fetch(core, sq_ring(core, array=False), cached_sq_head=2, sq_tail=4)
    assert got == [(3, 3, None, 4), (2, 2, None, 3), (1, 1, 0, 2), (0, 0, 1, 1)]


def test_sqes_after_the_tail_wrapped_still_list_the_pending_entries():
    slots = {3: ud(7), 0: ud(8)}
    core = sq_core(4, slots)
    got = fetch(core, sq_ring(core, array=False), cached_sq_head=0xFFFFFFFF, sq_tail=1)
    assert got[:2] == [(0, 0, None, 8), (0xFFFFFFFF, 3, None, 7)]


def test_sqes_never_used_slots_are_not_entries():
    core = sq_core(4, {1: ud(5)})
    assert fetch(core, sq_ring(core, array=False), cached_sq_head=3, sq_tail=3) == [
        (1, 1, 1, 5)
    ]


def test_sqes_of_a_128_byte_ring_are_128_bytes_apart():
    first = sqe_bytes("OPENAT", user_data=1)
    second = sqe_bytes("CLOSE", user_data=2)
    core = sq_core(2, {0: first, 1: second}, size=128)
    flags = io_uring.SETUP["SQE128"]
    got = fetch(
        core,
        sq_ring(core, array=False),
        flags=flags,
        sq_entries=2,
        cached_sq_head=2,
        sq_tail=2,
    )
    assert got == [(1, 1, 0, 2), (0, 0, 1, 1)]


def test_sqes_of_a_ring_without_sqe_memory_are_none_and_unreadable_memory_raises():
    core = sq_core(4, {})
    assert fetch(core, make_ring(core, sq_sqes=0, sq_array=0)) == []
    ring = make_ring(make_core(), sq_sqes=0x99000, sq_array=0)
    with pytest.raises(exceptions.InvalidAddressException):
        list(ring.core.reader.sqes(ring, make_state(cached_sq_head=1, sq_tail=1)))


def test_sqes_decode_the_fields_of_the_sqe():
    data = sqe_bytes(
        "OPENAT",
        flags=0b101,
        fd=-100,
        off=7,
        addr=0xA000,
        len=3,
        op_flags=0x42,
        user_data=0xDEADBEEF,
        buf_index=2,
        personality=1,
        file_index=4,
        addr3=9,
    )
    core = sq_core(4, {0: data})
    (e,) = core.sqes(
        sq_ring(core, array=False), make_state(cached_sq_head=1, sq_tail=1)
    )
    assert (io_uring.opname(e.opcode), e.flags, e.fd, e.off, e.addr, e.len) == (
        "OPENAT",
        5,
        -100,
        7,
        0xA000,
        3,
    )
    assert (
        e.op_flags,
        e.user_data,
        e.buf_index,
        e.personality,
        e.file_index,
        e.addr3,
    ) == (0x42, 0xDEADBEEF, 2, 1, 4, 9)


# --- the completion queue and the results -------------------------------------------------------------------


def cq_core(entries, tail, size=16):
    """A core whose CQ array holds completions 0..tail-1 the way the kernel wrote them (slot = number & mask)."""
    core = make_core()
    raw = bytearray(size * entries)
    for k in range(tail):
        slot = (k & (entries - 1)) * size
        raw[slot : slot + 16] = io_uring.CQE.pack(0x100 + k, k - 5, 0)
    core.layer.put(CQES, raw)
    return core


def test_cqes_after_the_ring_wrapped_hold_the_last_window_by_number():
    core = cq_core(4, 6)
    got = core.cqes(make_state(cq_entries=4, cq_tail=6))
    assert sorted(got) == [2, 3, 4, 5]
    assert got[5] == (0x105, 0, 0) and got[2] == (0x102, -3, 0)


def test_cqes_of_a_young_ring_start_at_zero():
    core = cq_core(8, 3)
    assert sorted(core.cqes(make_state(cq_entries=8, cq_tail=3))) == [0, 1, 2]


def test_cqes_of_a_cqe32_ring_are_32_bytes_apart():
    core = cq_core(2, 3, size=32)
    state = make_state(flags=io_uring.SETUP["CQE32"], cq_entries=2, cq_tail=3)
    assert core.cqes(state) == {1: (0x101, -4, 0), 2: (0x102, -3, 0)}


def entries_for(*specs):
    """Sqes for (seq, user_data, age) specs."""
    return [make_sqe("READ", seq=s, age=a, user_data=u) for s, u, a in specs]


def completions(st, entries, cqes):
    return [
        (e.result, e.completion)
        for e in io_uring.RingReader.match_results(st, entries, cqes)
    ]


def test_results_are_matched_by_a_unique_user_data():
    st = make_state(cq_tail=2, cached_sq_head=2)
    entries = entries_for((1, 0xB, 0), (0, 0xA, 1))
    cqes = {0: (0xA, 11, 0), 1: (0xB, -2, 0)}
    assert completions(st, entries, cqes) == [(-2, "user_data"), (11, "user_data")]


def test_results_by_order_when_user_data_is_left_zero():
    st = make_state(cq_tail=2, cached_sq_head=2)
    entries = entries_for((1, 0, 0), (0, 0, 1))
    cqes = {0: (0, 100, 0), 1: (0, 200, 0)}
    assert completions(st, entries, cqes) == [(200, "order"), (100, "order")]


def test_results_by_order_are_ambiguous_when_the_ring_completed_more_than_it_consumed():
    st = make_state(
        cq_tail=5, cached_sq_head=2
    )  # multishot or zero-copy posted extra CQEs
    entries = entries_for((1, 0, 0), (0, 0, 1))
    cqes = {0: (0, 100, 0), 1: (0, 200, 0)}
    assert completions(st, entries, cqes) == [(None, "ambiguous"), (None, "ambiguous")]


def test_results_in_flight_pending_and_gone():
    st = make_state(cq_tail=2, cached_sq_head=3)
    pending = make_sqe("READ", seq=3, age=None, user_data=1)
    in_flight = make_sqe("READ", seq=2, age=0, user_data=2)
    old = make_sqe("READ", seq=0, age=1, user_data=3)
    got = completions(st, [pending, in_flight, old], {1: (9, 1, 0)})
    assert got == [(None, "not submitted"), (None, "in flight"), (None, "not in CQ")]


def test_a_user_data_used_twice_is_not_matched_by_user_data():
    st = make_state(cq_tail=2, cached_sq_head=2)
    entries = entries_for((1, 7, 0), (0, 7, 1))
    cqes = {0: (7, 1, 0), 1: (7, 2, 0)}
    assert completions(st, entries, cqes) == [(2, "order"), (1, "order")]


def test_without_a_readable_cq_ring_the_results_are_unknown_not_missing():
    """Defect: an unreadable CQ ring made the whole Ops listing unreadable, the SQEs with it."""
    st = make_state()
    pending = make_sqe("READ", seq=3, age=None)
    done = make_sqe("READ", seq=1, age=0)
    got = completions(st, [pending, done], None)
    assert got == [(None, "not submitted"), (None, "CQ unreadable")]


# --- registered files and buffers --------------------------------------------------------------------------


def table_ring(entries, new=False, **kw):
    core = make_core(new_tables=new)
    core.layer.put(TABLE, struct.pack(f"<{len(entries)}Q", *entries))
    return make_ring(core, **kw)


def test_fixed_file_flag_bits_are_stripped_on_5x_and_6x_layouts():
    """5.x keeps three flag bits in file_ptr (NOWAIT, ISREG, SCM), 6.x two; an unset slot or one that holds only
    flags is not a file. Before the flags were stripped the paths were empty and still-open files looked hidden."""
    f1, f2, f3 = KERNEL, KERNEL + 0x1000, KERNEL + 0x2000
    entries = [0, f1 | 0b011, f2 | 0b111, 0b100, f3]
    ring = table_ring(entries, nr_user_files=5, file_table=SimpleNamespace(files=TABLE))
    assert list(ring.core.reader.fixed_files(ring)) == [(1, f1), (2, f2), (4, f3)]


def test_a_missing_fixed_file_table_has_no_files():
    ring = make_ring(nr_user_files=4, file_table=SimpleNamespace(files=0))
    assert list(ring.core.reader.fixed_files(ring)) == []


def test_the_fixed_file_count_of_a_smeared_ring_is_rejected_before_reading():
    ring = make_ring(
        nr_user_files=io_uring.MAX_FIXED_FILES + 1,
        file_table=SimpleNamespace(files=TABLE),
    )
    with pytest.raises(exceptions.InvalidAddressException):
        list(ring.core.reader.fixed_files(ring))


def test_an_unreadable_part_of_a_big_table_is_not_a_run_of_empty_slots():
    """Defect: one unreadable page lost the whole table (or, read padded, showed its slots as free); now the
    readable chunks are used and the unreadable one is one unreadable entry at its first slot."""
    core = make_core()
    first = [0] * io_uring.TABLE_CHUNK
    first[3] = KERNEL | 3
    core.layer.put(
        TABLE, struct.pack(f"<{len(first)}Q", *first)
    )  # the second chunk is not mapped
    ring = make_ring(
        core,
        nr_user_files=2 * io_uring.TABLE_CHUNK,
        file_table=SimpleNamespace(files=TABLE),
    )
    assert list(core.fixed_files(ring)) == [(3, KERNEL), (io_uring.TABLE_CHUNK, None)]


def test_a_table_whose_start_is_unreadable_raises():
    ring = make_ring(nr_user_files=4, file_table=SimpleNamespace(files=0x99000))
    with pytest.raises(exceptions.InvalidAddressException):
        list(ring.core.reader.fixed_files(ring))


CHUNK_A, CHUNK_B = 0x50000, 0x60000


def two_level_ring(nr, chunks, **kw):
    """A 5.13 / 5.14 ring: `files` at TABLE points to one pointer per 512-slot chunk; `chunks` is
    {address: slot values} for the chunks that are mapped."""
    core = make_core(two_level_files=True)
    level1 = [CHUNK_A, CHUNK_B][: -(-nr // io_uring.FILE_TABLE_CHUNK)]
    core.layer.put(TABLE, struct.pack(f"<{len(level1)}Q", *level1))
    for addr, slots in chunks.items():
        core.layer.put(addr, struct.pack(f"<{len(slots)}Q", *slots))
    return make_ring(
        core, nr_user_files=nr, file_table=SimpleNamespace(files=TABLE), **kw
    )


def test_fixed_files_of_5_13_and_5_14_are_read_through_the_two_levels():
    """Defect (found on a real 5.13 image): `files` there points to a table of pointers to 512-slot chunks
    (`io_fixed_file **`). It was read as the slots themselves: the chunk pointer showed as slot 0 and the heap
    behind the first level as slots 1 to nr_user_files - 1."""
    f1, f2, f3 = KERNEL, KERNEL + 0x1000, KERNEL + 0x2000
    first = [0] * io_uring.FILE_TABLE_CHUNK
    first[0], first[511] = f1 | 0b101, f2
    second = [0] * 88
    second[5] = f3 | 0b011
    ring = two_level_ring(600, {CHUNK_A: first, CHUNK_B: second})
    assert list(ring.core.reader.fixed_files(ring)) == [(0, f1), (511, f2), (517, f3)]


def test_a_small_5_13_table_is_one_chunk_cut_to_nr_user_files():
    ring = two_level_ring(3, {CHUNK_A: [KERNEL, 0, KERNEL + 0x1000, KERNEL + 0x2000]})
    # the fourth value is beyond nr_user_files and is not read
    assert list(ring.core.reader.fixed_files(ring)) == [
        (0, KERNEL),
        (2, KERNEL + 0x1000),
    ]


def test_an_unreadable_chunk_of_a_5_13_table_is_one_unreadable_slot_not_empty_slots():
    first = [0] * io_uring.FILE_TABLE_CHUNK
    first[1] = KERNEL
    ring = two_level_ring(600, {CHUNK_A: first})  # CHUNK_B is not mapped
    assert list(ring.core.reader.fixed_files(ring)) == [
        (1, KERNEL),
        (io_uring.FILE_TABLE_CHUNK, None),
    ]


def test_a_5_13_table_with_an_unreadable_first_level_raises():
    ring = two_level_ring(3, {})
    ring.core.reader.layer.regions.clear()
    with pytest.raises(exceptions.InvalidAddressException):
        list(ring.core.reader.fixed_files(ring))


def test_a_chunk_that_was_never_allocated_is_not_read_as_address_zero():
    core = make_core(two_level_files=True)
    core.layer.put(TABLE, struct.pack("<2Q", CHUNK_A, 0))
    core.layer.put(CHUNK_A, bytes(8 * io_uring.FILE_TABLE_CHUNK))
    ring = make_ring(core, nr_user_files=600, file_table=SimpleNamespace(files=TABLE))
    assert list(core.fixed_files(ring)) == [(io_uring.FILE_TABLE_CHUNK, None)]


class Template:
    def __init__(self, object_class=None):
        self.vol = {} if object_class is None else {"object_class": object_class}


def test_the_layouts_are_told_from_the_isf_types():
    """`files` of a 5.13 ring file table is a pointer to pointers, from 5.15 on a pointer to a struct;
    `registered_rings` is a pointer in 5.18 and 5.19 and an array from 6.0."""
    pointer, array = (
        Template(io_uring.objects.Pointer),
        Template(io_uring.objects.Array),
    )
    struct_template = Template()
    assert io_uring.KernelAccess.is_pointer(pointer)
    assert not io_uring.KernelAccess.is_pointer(array)
    assert not io_uring.KernelAccess.is_pointer(struct_template)


def core_of_kernel(monkeypatch, files=None, rings=None):
    """An `IoUringCore` set up from a fake symbol table. `files` is the template of what `io_file_table.files` points
    to (None: the 6.13 table with `data` instead), `rings` the template of `io_uring_task.registered_rings` (None: no
    such member)."""

    class Type:
        def __init__(self, members):
            self.members = members

        def has_member(self, name):
            return name in self.members

        def child_template(self, name):
            return self.members[name]

    types = {
        "io_file_table": Type(
            {"data": None}
            if files is None
            else {"files": SimpleNamespace(vol=SimpleNamespace(subtype=files))}
        ),
        "io_uring_task": Type({} if rings is None else {"registered_rings": rings}),
        "io_ring_ctx": Type({"personalities": None}),
    }
    kernel = SimpleNamespace(
        layer_name="layer",
        symbol_table_name="k",
        has_symbol=lambda name: True,
        has_type=lambda name: True,
        get_type=lambda name: types[name],
        object_from_symbol=lambda name: SimpleNamespace(vol=SimpleNamespace(offset=1)),
    )
    context = SimpleNamespace(modules={"kernel": kernel}, layers={"layer": Memory()})
    monkeypatch.setattr(io_uring.linux, "XArray", lambda *args: None)
    return io_uring.IoUringCore(context, "kernel")


def test_the_two_level_table_and_the_registered_rings_pointer_are_told_from_the_isf(
    monkeypatch,
):
    pointer, array, struct_type = (
        Template(io_uring.objects.Pointer),
        Template(io_uring.objects.Array),
        Template(),
    )
    # 5.15 to 5.17, 6.0 to 6.12: `io_fixed_file *files`, and `registered_rings` an array from 6.0
    flat = core_of_kernel(monkeypatch, struct_type, rings=array)
    assert not flat.reader.two_level_files and not flat.finder.rings_by_pointer
    # 5.13, 5.14: `io_fixed_file **files`, no `registered_rings`
    two_level = core_of_kernel(monkeypatch, pointer)
    assert two_level.reader.two_level_files and not two_level.finder.rings_by_pointer
    # 5.18, 5.19: `registered_rings` is a pointer
    assert core_of_kernel(
        monkeypatch, struct_type, rings=pointer
    ).finder.rings_by_pointer
    # 6.13 on: the table is `data` and `nodes`, whatever `files` was
    assert not core_of_kernel(monkeypatch, None, rings=array).reader.two_level_files


def test_fixed_files_from_6_13_are_read_through_their_nodes():
    """6.13 and later: the table holds io_rsrc_node pointers, the file pointer (and its flag bits) is in the node;
    a node that cannot be read is an unreadable slot, a table entry of 0 an empty one."""

    class Unreadable:
        @property
        def file_ptr(self):
            raise exceptions.InvalidAddressException("kernel", 0, "bad node")

    node_a, node_bad, node_free = (
        0xFFFF888000010000,
        0xFFFF888000020000,
        0xFFFF888000030000,
    )
    nodes = {
        node_a: SimpleNamespace(file_ptr=KERNEL | 0b10),
        node_bad: Unreadable(),
        node_free: SimpleNamespace(file_ptr=0),
    }
    ring = table_ring(
        [node_a, 0, node_bad, node_free],
        new=True,
        file_table=SimpleNamespace(data=SimpleNamespace(nr=4, nodes=TABLE)),
    )
    ring.core.reader.obj = lambda type_name, addr: nodes[addr]
    assert list(ring.core.reader.fixed_files(ring)) == [(0, KERNEL), (2, None)]


def imu_obj(ubuf=0x7F0000001000):
    """What `obj("io_mapped_ubuf", addr)` gives: only the `ubuf` field matters to the placeholder check."""
    return lambda type_name, addr: SimpleNamespace(
        type_name=type_name, addr=addr, ubuf=ubuf
    )


def test_registered_buffers_skip_the_dummy_and_empty_entries_before_6_13():
    dummy, imu = 0xFFFF888000090000, 0xFFFF888000091000
    ring = table_ring(
        [dummy, imu, 0],
        nr_user_bufs=3,
        user_bufs=TABLE,
        dummy_ubuf=dummy,
        has_member=lambda name: name == "dummy_ubuf",
    )
    ring.core.reader.obj = lambda t, a: SimpleNamespace(
        addr=a, ubuf=0x1000 if a == imu else io_uring.UBUF_UNUSED
    )
    assert [(i, b.addr) for i, b in ring.core.reader.buffers(ring)] == [(1, imu)]


def test_the_dummy_buffer_is_found_although_the_framework_masks_pointer_values():
    """Defect (5.13 to 6.10, found on real images): `ctx.dummy_ubuf` reads as a masked address (top 16 bits
    cleared), the table entries are raw kernel addresses; they never compared equal, the placeholder of an empty
    slot was listed as a buffer, and its length (ubuf_end - ubuf, negative) crashed the Buffers plugin."""
    dummy, imu = 0xFFFF888000090000, 0xFFFF888000091000
    ring = table_ring(
        [dummy, imu],
        nr_user_bufs=2,
        user_bufs=TABLE,
        dummy_ubuf=dummy & 0x0000FFFFFFFFFFFF,
        has_member=lambda name: name == "dummy_ubuf",
    )
    # the placeholder is recognised by its address alone: reading it must not even be needed
    ring.core.reader.obj = lambda t, a: SimpleNamespace(addr=a, ubuf=0x1000)
    assert [(i, b.addr) for i, b in ring.core.reader.buffers(ring)] == [(1, imu)]


def test_an_empty_buffer_slot_is_skipped_from_6_11_on_where_the_placeholder_is_a_static_object():
    """Defect (6.11, 6.12, found on a real image): `dummy_ubuf` is no member of the ring there, empty slots point to
    one static `io_mapped_ubuf` with `ubuf` -1UL, and every empty slot was listed as a buffer."""
    static, imu = 0xFFFFFFFF83000000, 0xFFFF888000091000
    ring = table_ring(
        [imu, static], nr_user_bufs=2, user_bufs=TABLE, has_member=lambda name: False
    )
    ring.core.reader.obj = lambda t, a: SimpleNamespace(
        addr=a, ubuf=io_uring.UBUF_UNUSED if a == static else 0x7F0000001000
    )
    assert [(i, b.addr) for i, b in ring.core.reader.buffers(ring)] == [(0, imu)]


def test_a_buffer_whose_placeholder_check_cannot_be_read_stays_listed_for_the_plugin_to_show_as_unreadable():
    imu = 0xFFFF888000091000
    ring = table_ring(
        [imu], nr_user_bufs=1, user_bufs=TABLE, has_member=lambda name: False
    )

    class Gone:
        @property
        def ubuf(self):
            raise exceptions.InvalidAddressException("kernel", imu, "unmapped")

    ring.core.reader.obj = lambda t, a: Gone()
    assert [i for i, _ in ring.core.reader.buffers(ring)] == [0]


def test_a_negative_length_is_rejected_like_one_the_kernel_cannot_have():
    core = make_core()
    with pytest.raises(exceptions.InvalidAddressException):
        core.sane(-1, io_uring.MAX_BUFFER, "buffer bytes")
    placeholder = SimpleNamespace(
        has_member=lambda name: False, ubuf=io_uring.UBUF_UNUSED, ubuf_end=0
    )
    assert io_uring.RingReader.buffer_len(placeholder) < 0


def test_registered_buffers_from_6_13_come_from_the_nodes_and_unreadable_nodes_stay_visible():
    imu = 0xFFFF888000091000
    node_ok, node_bad = 0xFFFF888000010000, 0xFFFF888000020000

    def obj(type_name, addr):
        if addr == node_bad:
            raise exceptions.InvalidAddressException("kernel", addr, "bad")
        return SimpleNamespace(buf=imu) if addr == node_ok else (type_name, addr)

    ring = table_ring(
        [0, node_ok, node_bad], new=True, buf_table=SimpleNamespace(nr=3, nodes=TABLE)
    )
    ring.core.reader.obj = lambda t, a: obj(t, a) if t == "io_rsrc_node" else (t, a)
    # the bad node raises when it is constructed here, which `_rsrc_pointer` treats like a bad field read
    ring.core.reader._is_placeholder = lambda addr: False
    assert list(ring.core.reader.buffers(ring)) == [
        (1, ("io_mapped_ubuf", imu)),
        (2, None),
    ]


def test_buffer_length_before_and_after_6_12():
    new = SimpleNamespace(has_member=lambda name: name == "len", len=4096)
    old = SimpleNamespace(has_member=lambda name: False, ubuf=0x1000, ubuf_end=0x2800)
    assert io_uring.RingReader.buffer_len(new) == 4096
    assert io_uring.RingReader.buffer_len(old) == 0x1800


# --- buffer contents ----------------------------------------------------------------------------------------


BVEC = 0x9000
PAGE_A, PAGE_B = 0x100000, 0x200000


def buffer_core(segments, phys=None):
    """A core whose bio_vecs at BVEC.. are `segments`: (page paddr, offset, length) or an exception for a bio_vec
    that cannot be read; `phys` maps paddr -> bytes of the pages the image holds."""
    core = make_core()
    memory = Memory()
    for addr, data in (phys or {}).items():
        memory.put(addr, data)
    core.context.layers["phys"] = memory
    vecs = {}
    for i, seg in enumerate(segments):
        if isinstance(seg, Exception):
            continue
        paddr, offset, length = seg
        page = SimpleNamespace(
            dereference=lambda p=paddr: SimpleNamespace(to_paddr=lambda: p)
        )
        vecs[BVEC + i * 16] = SimpleNamespace(
            bv_len=length, bv_offset=offset, bv_page=page
        )

    def obj(type_name, addr):
        if addr not in vecs:
            raise exceptions.InvalidAddressException("kernel", addr, "bad bio_vec")
        return vecs[addr]

    core.obj = obj
    return core


def imu_of(length, nr):
    return SimpleNamespace(
        has_member=lambda name: name == "len",
        len=length,
        nr_bvecs=nr,
        bvec=SimpleNamespace(vol=SimpleNamespace(offset=BVEC)),
    )


PAGES = {PAGE_A: bytes(range(256)) * 16, PAGE_B: b"B" * 4096}


def test_buffer_bytes_joins_the_segments_from_the_offset_of_the_first_one():
    core = buffer_core([(PAGE_A, 0x80, 100), (PAGE_B, 0, 50)], PAGES)
    data, missing, length = core.buffer_bytes(imu_of(150, 2))
    assert (missing, length) == (0, 150)
    assert data == PAGES[PAGE_A][0x80 : 0x80 + 100] + b"B" * 50


def test_buffer_bytes_with_a_limit_reads_only_what_the_limit_needs():
    core = buffer_core([(PAGE_A, 0, 100), (PAGE_B, 0, 50)], PAGES)
    data, missing, length = core.buffer_bytes(imu_of(150, 2), 10)
    assert (data, missing, length) == (PAGES[PAGE_A][:10], 0, 150)


def test_a_page_the_image_does_not_hold_is_counted_missing():
    """Defect: the page read was padded with zeros, so a pinned page that is not in the image showed as 4096
    bytes of zeros and `Missing bytes` said 0."""
    core = buffer_core([(PAGE_A, 0, 100), (PAGE_B, 0, 50)], {PAGE_A: PAGES[PAGE_A]})
    data, missing, length = core.buffer_bytes(imu_of(150, 2))
    assert missing == 50 and data == PAGES[PAGE_A][:100] + bytes(50)


def test_a_bio_vec_longer_than_the_buffer_is_cut_to_the_buffer():
    """Defect: a corrupt `bv_len` was read in full (a folio's bio_vec can be 1 GiB)."""
    core = buffer_core([(PAGE_A, 0, 1 << 40)], PAGES)
    data, missing, length = core.buffer_bytes(imu_of(64, 1))
    assert (len(data), missing) == (64, 0)


def test_an_unreadable_bio_vec_makes_the_rest_of_the_buffer_missing():
    core = buffer_core([(PAGE_A, 0, 100), RuntimeError("unreadable")], PAGES)
    data, missing, length = core.buffer_bytes(imu_of(150, 2))
    assert (len(data), missing) == (150, 50)
    assert data[:100] == PAGES[PAGE_A][:100] and data[100:] == bytes(50)


def test_bio_vecs_that_cover_less_than_the_length_leave_the_difference_missing():
    core = buffer_core([(PAGE_A, 0, 100)], PAGES)
    data, missing, length = core.buffer_bytes(imu_of(150, 1))
    assert (len(data), missing) == (150, 50)


def test_a_buffer_longer_than_the_kernel_allows_is_rejected():
    core = buffer_core([(PAGE_A, 0, 100)], PAGES)
    with pytest.raises(exceptions.InvalidAddressException):
        core.buffer_bytes(imu_of(io_uring.MAX_BUFFER + 1, 1))


def test_a_page_struct_without_a_physical_address_counts_as_missing():
    core = buffer_core([(PAGE_A, 0, 100)], PAGES)
    core.obj = lambda t, a: SimpleNamespace(bv_len=100, bv_offset=0, bv_page=None)
    data, missing, _ = core.buffer_bytes(imu_of(100, 1))
    assert (data, missing) == (bytes(100), 100)


# --- personalities and credentials --------------------------------------------------------------------------


def test_cred_ids_read_the_capabilities_of_both_layouts():
    caps = 0x1FFFFFFFFFF
    new = SimpleNamespace(has_member=lambda name: name == "val", val=caps)
    old = SimpleNamespace(
        has_member=lambda name: name == "cap", cap=[0xFFFFFFFF, 0x1FF]
    )
    for cap in (new, old):
        cred = SimpleNamespace(
            uid=1000, euid=1000, gid=100, egid=101, cap_effective=cap
        )
        assert io_uring.RingReader.cred_ids(cred) == (1000, 1000, 100, 101, caps)


def cred_ring(creds, task_cred="task"):
    core = make_core(cred_ids=lambda cred: creds[cred])
    ring = make_ring(core)
    ring.task = SimpleNamespace(cred=task_cred)
    return ring


def test_personalities_that_differ_from_the_task_are_flagged():
    creds = {
        "task": (65534,) * 4 + (0,),
        "root": (0,) * 4 + (0x1FF,),
        "same": (65534,) * 4 + (0,),
    }
    ring = cred_ring(creds)
    got = list(io_uring.personality_ids(ring, [(1, "root"), (2, "same")]))
    assert got == [
        (1, creds["root"], creds["task"], True),
        (2, creds["same"], creds["task"], False),
    ]


def test_a_cred_that_cannot_be_read_gives_no_comparison():
    def cred_ids(cred):
        if cred == "bad":
            raise exceptions.InvalidAddressException("kernel", 1, "bad")
        return (1, 1, 1, 1, 0)

    ring = make_ring(make_core(cred_ids=cred_ids))
    ring.task = SimpleNamespace(cred="task")
    assert list(io_uring.personality_ids(ring, [(3, "bad")])) == [
        (3, None, (1, 1, 1, 1, 0), None)
    ]
    ring.task = SimpleNamespace(
        cred="bad"
    )  # the task's own cred is unreadable: nothing can be compared
    assert list(io_uring.personality_ids(ring, [(3, "ok")])) == [
        (3, (1, 1, 1, 1, 0), None, None)
    ]


# --- xarrays (personalities and the thread's rings) -----------------------------------------------------------


class Node:
    def __init__(self, shift, slots=None):
        self.shift = shift
        self.slots = [0] * 64
        for i, value in (slots or {}).items():
            self.slots[i] = value


def internal(addr):
    return addr | 2  # xa_mk_internal() of a node pointer


def xa_core(nodes, cls=io_uring.RingReader):
    """A `cls` whose xarray reads nodes from the dict (or the function) `nodes`."""
    core = make_core(cls)
    xa = object.__new__(
        linux.XArray
    )  # the framework's tag logic, without a symbol table
    xa.CHUNK_SIZE = 64
    xa.nodep_to_node = nodes if callable(nodes) else nodes.__getitem__
    core.xa = xa
    return core


def test_xa_entries_walks_the_tree_with_the_indexes():
    nodes = {
        0x10000: Node(6, {0: internal(0x11000), 2: internal(0x12000)}),
        0x11000: Node(0, {1: 0xAAA0, 5: 0xBBB0}),
        0x12000: Node(0, {0: 0xCCC0}),
    }
    core = xa_core(nodes)
    got = list(core.xa_entries(internal(0x10000)))
    assert got == [(1, 0xAAA0), (5, 0xBBB0), (128, 0xCCC0)]


def test_xa_entries_a_single_entry_is_at_index_0_and_a_value_is_not_an_entry():
    core = xa_core({})
    assert list(core.xa_entries(0xFFFF888000010000)) == [(0, 0xFFFF888000010000)]
    assert list(core.xa_entries(0x1235)) == []  # xa_mk_value(): the low bits are a tag
    assert list(core.xa_entries(0)) == []


def test_xa_entries_skip_sibling_retry_and_value_entries():
    nodes = {
        0x10000: Node(0, {0: (3 << 2) | 2, 1: 257 << 2 | 2, 2: 0x777, 3: 0xAAA0}),
    }
    assert list(xa_core(nodes).xa_entries(internal(0x10000))) == [(3, 0xAAA0)]


def test_xa_entries_stop_at_a_node_that_is_not_below_its_parent():
    """Defect: the framework's walk followed a corrupt node that pointed back to itself for as many levels as its
    `shift` said, 64 slots wide; here the node must lie below its parent."""
    nodes = {
        0x10000: Node(6, {0: internal(0x11000), 1: internal(0x10000)}),
        0x11000: Node(6, {0: 0xAAA0}),
    }
    assert list(xa_core(nodes).xa_entries(internal(0x10000))) == []


def test_xa_entries_stop_after_a_bounded_number_of_nodes():
    """A tree of junk that is full at every level (64 * 64 * 64 leaf entries) is cut off, not walked."""
    calls = []

    def node_at(addr):
        calls.append(addr)
        level = addr >> 28
        if level == 0:
            return Node(12, {i: internal((1 << 28) | (i << 16)) for i in range(64)})
        if level == 1:
            return Node(
                6,
                {
                    i: internal((2 << 28) | ((addr >> 16 & 63) << 22) | (i << 16))
                    for i in range(64)
                },
            )
        return Node(0, {i: 0x1000 * (i + 1) for i in range(64)})

    got = list(xa_core(node_at).xa_entries(internal(0x10000)))
    assert len(calls) == io_uring.MAX_XA_NODES
    assert len(got) <= 64 * io_uring.MAX_XA_NODES


def test_personalities_are_the_creds_with_their_ids_up_to_the_largest_one():
    nodes = {0x10000: Node(0, {1: 0xC1C0, 63: 0xC2C0}), 0x11000: Node(0, {0: 0xC3C0})}
    nodes[0x20000] = Node(12, {0: internal(0x10000), 1: internal(0x11000)})
    core = xa_core(nodes)
    core.obj = lambda type_name, addr: (type_name, addr)
    # the second child starts at index 1 << 12 = 4096 (still a valid id), a third would be beyond 65535
    ring = make_ring(core, personalities=SimpleNamespace(xa_head=internal(0x20000)))
    assert list(core.personalities(ring)) == [
        (1, ("cred", 0xC1C0)),
        (63, ("cred", 0xC2C0)),
        (4096, ("cred", 0xC3C0)),
    ]
    nodes[0x20000] = Node(
        18, {0: internal(0x10000), 1: internal(0x11000)}
    )  # 1 << 18 > 65535
    assert [i for i, _ in core.personalities(ring)] == [1, 63]


# --- finding rings --------------------------------------------------------------------------------------------


def task(files=1, pid=7):
    return SimpleNamespace(
        files=files,
        mm=1,
        pid=pid,
        comm=f"p{pid}",
        vol=SimpleNamespace(offset=pid),
        get_threads=list,
    )


def patch_tasks(monkeypatch, tasks):
    monkeypatch.setattr(
        pslist.PsList,
        "list_tasks",
        classmethod(lambda cls, context, name, flt, include_threads=False: iter(tasks)),
    )


def test_processes_skips_a_task_that_cannot_be_read_and_goes_on(monkeypatch):
    """One task that cannot be read does not end the listing."""

    def broken():
        raise exceptions.InvalidAddressException("kernel", 1, "gone")

    bad = task(pid=5)
    bad.get_threads = broken
    patch_tasks(monkeypatch, [bad, task(pid=6)])
    got = [
        (pid, comm)
        for _threads, _task, pid, comm in make_core(io_uring.RingFinder).processes(
            lambda _: False
        )
    ]
    assert got == [(6, "p6")]


def test_processes_read_fds_and_memory_from_a_thread_when_the_leader_has_exited(
    monkeypatch,
):
    leader = task(files=0)
    leader.mm = 0
    thread = task(pid=8)
    leader.get_threads = lambda: [thread]
    patch_tasks(monkeypatch, [leader])
    ((threads, chosen, pid, _comm),) = make_core(io_uring.RingFinder).processes(
        lambda _: False
    )
    assert (chosen, pid, threads) == (thread, 7, [leader, thread])


def test_distinct_fd_tables_gives_one_thread_per_table():
    shared_a, shared_b = task(files=0x100, pid=1), task(files=0x100, pid=2)
    own = task(files=0x200, pid=3)
    exited = task(files=0, pid=4)

    class Freed:
        @property
        def files(self):
            raise exceptions.InvalidAddressException("kernel", 1, "freed")

    threads = [shared_a, shared_b, own, exited, Freed()]
    assert list(io_uring.RingFinder.distinct_fd_tables(threads)) == [shared_a, own]


def test_a_file_that_only_a_thread_with_its_own_fd_table_holds_is_not_hidden(
    monkeypatch,
):
    """Defect: only the first thread's fd table was read, so a file open in a thread that called
    unshare(CLONE_FILES) was reported as hidden from every fd table."""
    main, helper = task(files=0x100, pid=7), task(files=0x200, pid=8)
    core = make_core(io_uring.RingFinder)
    monkeypatch.setattr(
        core, "processes", lambda flt: iter([([main, helper], main, 7, "p7")])
    )
    tables = {0x100: [(3, 0xA0)], 0x200: [(9, 0xB0)]}
    monkeypatch.setattr(core, "fd_table", lambda t: iter(tables[t.files]))
    assert core.fd_owners() == {0xA0: [(7, 3)], 0xB0: [(7, 9)]}


def test_fd_table_lists_the_open_files_and_gives_up_on_a_corrupt_table(monkeypatch):
    core = make_core(io_uring.RingFinder)
    monkeypatch.setattr(
        io_uring.utility,
        "array_of_pointers",
        lambda *a, **kw: [0, KERNEL & ~(0xFFFF << 48), 0, 0x1000],
    )

    def with_files(max_fds):
        files = SimpleNamespace(get_fds=lambda: 0x5000, get_max_fds=lambda: max_fds)
        return SimpleNamespace(files=files, vol=SimpleNamespace(offset=1))

    assert list(core.fd_table(with_files(4))) == [
        (1, 0xFFFF000000000000 | (KERNEL & ~(0xFFFF << 48))),
        (3, 0x1000),
    ]
    assert list(core.fd_table(with_files(io_uring.MAX_FDS + 1))) == []
    assert (
        list(core.fd_table(SimpleNamespace(files=0, vol=SimpleNamespace(offset=1))))
        == []
    )

    class Unreadable:
        vol = SimpleNamespace(offset=1)

        @property
        def files(self):
            raise exceptions.InvalidAddressException("kernel", 1, "gone")

    assert list(core.fd_table(Unreadable())) == []


def test_ctx_of_file_is_the_ring_of_an_io_uring_file_only():
    ring_file = SimpleNamespace(
        f_op=0xFFFFFFFF82000000, private_data=KERNEL & ~(0xFFFF << 48)
    )
    other = SimpleNamespace(f_op=0xFFFFFFFF82009999, private_data=KERNEL)
    core = make_core(io_uring.RingFinder)
    files = {0x1: ring_file, 0x2: other}

    def obj(type_name, addr):
        if addr not in files:
            raise exceptions.InvalidAddressException("kernel", addr, "bad file")
        return files[addr]

    core.obj = obj
    assert core.ctx_of_file(1) == 0xFFFF000000000000 | (KERNEL & ~(0xFFFF << 48))
    assert core.ctx_of_file(2) is None
    assert core.ctx_of_file(3) is None


def test_find_rings_gives_one_ring_per_process_with_every_place_it_was_found(
    monkeypatch,
):
    core = make_core(io_uring.RingFinder)
    core.obj = lambda type_name, addr: SimpleNamespace(addr=addr)
    monkeypatch.setattr(
        core,
        "processes",
        lambda flt: iter([([], task(), 7, "p7"), ([], task(pid=9), 9, "p9")]),
    )
    monkeypatch.setattr(
        core, "_from_fds", lambda t: iter([(0x1000, "fd 3", 3), (0x2000, "fd 4", 4)])
    )
    monkeypatch.setattr(
        core, "_from_tctx", lambda ts: iter([(0x1000, "tctx (tid 7)", None)])
    )
    monkeypatch.setattr(
        core,
        "_from_vmas",
        lambda t: iter([(0x1000, "mmap", None), (0x1000, "mmap", None)]),
    )
    rings = list(core.find_rings("core"))
    assert all(r.core == "core" and r.ctx.addr == r.addr for r in rings)
    assert [(r.pid, r.addr, r.sources, r.fds) for r in rings] == [
        (7, 0x1000, ["fd 3", "tctx (tid 7)", "mmap"], [3]),
        (7, 0x2000, ["fd 4"], [4]),
        (9, 0x1000, ["fd 3", "tctx (tid 7)", "mmap"], [3]),
        (9, 0x2000, ["fd 4"], [4]),
    ]


def thread(tid, registered=(), xa_head=0, error=False):
    def io_uring_task():
        if error:
            raise exceptions.InvalidAddressException("kernel", tid, "gone")
        return SimpleNamespace(
            registered_rings=registered
            if isinstance(registered, int)
            else list(registered),
            xa=SimpleNamespace(xa_head=xa_head),
            has_member=lambda name: name == "registered_rings",
        )

    class Thread:
        pid = tid
        vol = SimpleNamespace(offset=tid)
        io_uring = SimpleNamespace(dereference=io_uring_task)

        @staticmethod
        def has_member(name):
            return name == "io_uring"

    return Thread()


def test_rings_of_a_thread_come_from_its_registered_slots_and_its_xarray_and_a_bad_thread_is_skipped():
    core = xa_core({0x10000: Node(0, {7: 0x5100})}, io_uring.RingFinder)
    core.ctx_of_file = lambda filp: {0x42: KERNEL}.get(filp)
    core.obj = lambda type_name, addr: SimpleNamespace(ctx=0x1234000)
    core.layer = Memory()
    threads = [
        thread(3, error=True),
        thread(4, registered=[0, 0x42, 0x99], xa_head=internal(0x10000)),
    ]
    got = list(core._from_tctx(threads))
    assert got == [
        (KERNEL, "registered ring 1 (tid 4)", None),
        (0x1234000, "tctx (tid 4)", None),
    ]


RING_FILES = 0x70000


def pointer_core(files=None):
    """A 5.18 / 5.19 core: `registered_rings` is a pointer to RING_FD_REG_MAX file pointers at RING_FILES."""
    core = xa_core({0x10000: Node(0, {7: 0x5100})}, io_uring.RingFinder)
    core.rings_by_pointer = True
    core.ctx_of_file = lambda filp: {0x42: KERNEL}.get(filp)
    core.obj = lambda type_name, addr: SimpleNamespace(ctx=0x1234000)
    if files is not None:
        padded = list(files) + [0] * (io_uring.RING_FD_REG_MAX - len(files))
        core.layer.put(RING_FILES, struct.pack("<16Q", *padded))
    return core


def test_registered_rings_of_5_18_and_5_19_are_read_through_the_pointer():
    """Defect (found on a real 5.19 image): `registered_rings` is a pointer to the array there; iterating it
    raised TypeError and the plugins failed on every process with an io_uring_task."""
    core = pointer_core([0, 0x42, 0x99])
    got = list(
        core._from_tctx([thread(4, registered=RING_FILES, xa_head=internal(0x10000))])
    )
    assert got == [
        (KERNEL, "registered ring 1 (tid 4)", None),
        (0x1234000, "tctx (tid 4)", None),
    ]


def test_a_thread_without_a_registered_rings_array_still_gives_its_xarray_rings():
    for pointer, files in ((0, None), (0x99000, None)):  # never allocated, unreadable
        core = pointer_core(files)
        got = list(
            core._from_tctx([thread(4, registered=pointer, xa_head=internal(0x10000))])
        )
        assert got == [(0x1234000, "tctx (tid 4)", None)]


def test_rings_of_a_task_without_io_uring_state_are_none():
    quiet = SimpleNamespace(
        has_member=lambda name: True, io_uring=0, vol=SimpleNamespace(offset=1)
    )
    assert list(make_core(io_uring.RingFinder)._from_tctx([quiet])) == []


def test_rings_mapped_into_a_process_are_found_through_the_vma_file(monkeypatch):
    core = make_core(io_uring.RingFinder)
    vmas = [
        SimpleNamespace(vm_file=0x42),
        SimpleNamespace(vm_file=0),
        SimpleNamespace(vm_file=0x43),
    ]
    monkeypatch.setattr(io_uring, "vma_iter", lambda mm: iter(vmas))
    core.ctx_of_file = lambda filp: KERNEL if filp == 0x42 else None
    mapped = SimpleNamespace(mm=1, vol=SimpleNamespace(offset=1))
    assert list(core._from_vmas(mapped)) == [(KERNEL, "mmap", None)]
    assert list(core._from_vmas(SimpleNamespace(mm=0))) == []


# --- describing fixed files ---------------------------------------------------------------------------------


def test_sock_handlers_are_built_once_per_task(monkeypatch):
    """Defect: a `SockHandlers` (which walks every network device) was built for every socket of every ring."""
    built = []

    class Counting:
        def __init__(self, *args):
            built.append(args)

    monkeypatch.setattr(io_uring.sockstat, "SockHandlers", Counting)
    core = make_core(io_uring.RingDecoder)
    task_a, task_b = (
        SimpleNamespace(vol=SimpleNamespace(offset=1)),
        SimpleNamespace(vol=SimpleNamespace(offset=2)),
    )
    assert core.sock_handlers(task_a) is core.sock_handlers(task_a)
    assert core.sock_handlers(task_b) is not core.sock_handlers(task_a)
    assert len(built) == 2


def socket_core(stat, family="AF_INET", sk_common=None):
    core = make_core(io_uring.RingDecoder)
    sk = SimpleNamespace(get_family=lambda: family)
    if sk_common is not None:
        sk.__dict__["__sk_common"] = sk_common
    child = SimpleNamespace(get_protocol=lambda: "TCP")
    core.sock_handlers = lambda t: SimpleNamespace(
        process_sock=lambda s: (child, stat, {})
    )
    core.obj = lambda type_name, addr: SimpleNamespace(
        sk=SimpleNamespace(dereference=lambda: sk)
    )
    return core


def test_a_socket_is_described_by_family_protocol_ends_and_state():
    core = socket_core(("127.0.0.1", 40434, "127.0.0.1", 47102, "ESTABLISHED"))
    f = SimpleNamespace(private_data=0x1000)
    assert (
        core._describe_socket(None, f)
        == "AF_INET/TCP 127.0.0.1:40434 -> 127.0.0.1:47102 ESTABLISHED"
    )


def test_an_ipv6_socket_without_addresses_from_the_framework_is_read_from_sock_common():
    """vol3 2.28.2 gives no addresses for AF_INET6 on a macOS or Windows host."""
    loopback = bytes(15) + b"\x01"
    common = v6_socket(loopback, loopback).__dict__["__sk_common"]
    core = socket_core((None, 22, None, 5000, "LISTEN"), "AF_INET6", common)
    assert (
        core._describe_socket(None, SimpleNamespace(private_data=1))
        == "AF_INET6/TCP ::1:22 -> ::1:5000 LISTEN"
    )


def file_core(f_op, monkeypatch=None):
    core = make_core(io_uring.RingDecoder)
    core.obj = lambda type_name, addr: SimpleNamespace(f_op=f_op)
    return core


def test_describe_file_gives_socket_details_or_the_path(monkeypatch):
    core = file_core(0xFFFFFFFF82001000)
    core._describe_socket = lambda task, f: "AF_INET/TCP a -> b ESTABLISHED"
    assert core.describe_file(None, 1) == ("socket", "AF_INET/TCP a -> b ESTABLISHED")
    monkeypatch.setattr(
        io_uring.linux.LinuxUtilities,
        "path_for_file",
        classmethod(lambda cls, ctx, task, f: "/tmp/x"),
    )
    assert file_core(0xFFFFFFFF82009999).describe_file(None, 1) == ("file", "/tmp/x")


def test_describe_file_unreadable_parts_are_unreadable_cells(monkeypatch):
    core = file_core(0xFFFFFFFF82001000)

    def broken(task, f):
        raise exceptions.SymbolError("x", "k", "no unix_sock")

    core._describe_socket = broken
    kind, text = core.describe_file(None, 1)
    assert kind == "socket" and isinstance(text, renderers.UnreadableValue)

    def no_path(cls, ctx, task, f):
        raise exceptions.InvalidAddressException("kernel", 1, "dentry")

    monkeypatch.setattr(
        io_uring.linux.LinuxUtilities, "path_for_file", classmethod(no_path)
    )
    kind, text = file_core(0xFFFFFFFF82009999).describe_file(None, 1)
    assert kind == "file" and isinstance(text, renderers.UnreadableValue)


def test_describe_file_does_not_call_an_unreadable_file_a_socket():
    """Defect: a struct file whose `f_op` could not be read was labelled `socket`."""

    class Bad:
        @property
        def f_op(self):
            raise exceptions.InvalidAddressException("kernel", 1, "bad file")

    core = make_core(io_uring.RingDecoder)
    core.obj = lambda type_name, addr: Bad()
    kind, text = core.describe_file(None, 1)
    assert isinstance(kind, renderers.UnreadableValue) and isinstance(
        text, renderers.UnreadableValue
    )


# --- the plugins' rows -------------------------------------------------------------------------------------


def plugin_ring(**core_attrs):
    """A ring whose core is a stub that answers what the plugins ask, with typed readable values. `core_attrs` go
    to the stub of whichever of finder, reader and decoder has them."""
    reader = make_core(io_uring.RingReader)
    finder = make_core(io_uring.RingFinder)
    decoder = make_core(io_uring.RingDecoder)
    thread = SimpleNamespace(pid=94, comm="iou-sqp-89")
    defaults = dict(
        ring_state=lambda ring: make_state(
            flags=io_uring.SETUP["SQPOLL"], sq_head=3, sq_tail=4, cq_head=3, cq_tail=3
        ),
        fixed_files=lambda ring: iter([(0, 0xA0), (2, None), (3, 0xB0)]),
        buffers=lambda ring: iter([]),
        personalities=lambda ring: iter([]),
        sq_thread=lambda ring, st: (thread.pid, thread.comm),
        ring_owners=dict,
        fd_owners=lambda: {0xA0: [(5, 3), (6, 4)]},
        describe_file=lambda task, filp: ("file", f"/f/{filp:x}"),
        cred_ids=lambda cred: (0, 0, 0, 0, 0),
    )
    for name, value in {**defaults, **core_attrs}.items():
        owner = next(o for o in (reader, finder, decoder) if hasattr(type(o), name))
        setattr(owner, name, value)
    ring = make_ring(reader)
    ring.core.finder, ring.core.decoder = finder, decoder
    return ring


def test_rings_row_is_typed_and_says_what_is_unusual():
    ring = plugin_ring(
        buffers=lambda r: iter([(0, "imu")]),
        personalities=lambda r: iter([(1, "cred")]),
        cred_ids=lambda cred: (
            (0, 0, 0, 0, 1) if cred == "cred" else (65534, 65534, 65534, 65534, 0)
        ),
    )
    ring.fds = []
    ring.core.finder.ring_owners = lambda: {ring.addr: [(11, 4)]}
    (row,) = populate(make_plugin(io_uring.Rings, [ring]))
    assert row[:3] == (7, "probe", io_uring.format_hints.Hex(ring.addr))
    values = dict(
        zip([n for n, _ in io_uring.Rings._HEAD + io_uring.Rings._columns], row)
    )
    assert values["Found via"] == "fd 3" and values["Setup flags"] == "SQPOLL"
    assert [
        values[k] for k in ("SQ entries", "SQ head", "SQ tail", "CQ head", "CQ tail")
    ] == [4, 3, 4, 3, 3]
    assert [values[k] for k in ("Fixed files", "Buffers", "Personalities")] == [3, 1, 1]
    assert (values["SQ thread"], values["SQ thread TID"]) == ("iou-sqp-89", 94)
    assert values["Notes"] == (
        "NO FD in this process (fd in 11:4); SQPOLL: submissions need no syscalls; "
        "personality 1 creds differ from task"
    )


def test_rings_row_of_a_quiet_ring_has_empty_notes_and_no_thread():
    ring = plugin_ring(
        ring_state=lambda r: make_state(sq_entries=16),
        sq_thread=lambda r, st: None,
    )
    (row,) = populate(make_plugin(io_uring.Rings, [ring]))
    values = dict(
        zip([n for n, _ in io_uring.Rings._HEAD + io_uring.Rings._columns], row)
    )
    assert values["Notes"] == "" and values["Setup flags"] == ""
    for name in ("SQ thread", "SQ thread TID"):
        assert isinstance(values[name], renderers.NotAvailableValue)


def test_rings_row_without_a_readable_ring_state_is_unreadable_not_zero():
    def broken(ring):
        raise exceptions.InvalidAddressException("kernel", 1, "freed")

    ring = plugin_ring(ring_state=broken)
    (row,) = populate(make_plugin(io_uring.Rings, [ring]))
    names = [n for n, _ in io_uring.Rings._HEAD + io_uring.Rings._columns]
    values = dict(zip(names, row))
    for name in (
        "Setup flags",
        "SQ entries",
        "SQ head",
        "CQ tail",
        "SQ thread",
        "SQ thread TID",
    ):
        assert isinstance(values[name], renderers.UnreadableValue), name
    assert "ring state unreadable" in values["Notes"]


def test_rings_mixed_size_and_unreadable_sq_thread_are_noted_and_shown():
    ring = plugin_ring(
        ring_state=lambda r: make_state(
            flags=io_uring.SETUP["SQPOLL"] | io_uring.SETUP_MIXED
        ),
        sq_thread=lambda r, st: (_ for _ in ()).throw(
            exceptions.InvalidAddressException("kernel", 1, "x")
        ),
    )
    (row,) = populate(make_plugin(io_uring.Rings, [ring]))
    assert all(isinstance(v, renderers.UnreadableValue) for v in row[-3:-1])
    assert "mixed-size entries: Ops not decoded" in row[-1]


def test_a_ring_that_cannot_be_read_is_one_unreadable_row_and_the_next_ring_still_comes():
    def broken(ring):
        raise exceptions.InvalidAddressException("kernel", 1, "freed")

    bad = plugin_ring(fixed_files=broken)
    good = plugin_ring()
    rows = populate(make_plugin(io_uring.Files, [bad, good]))
    first = rows[0]
    assert all(isinstance(v, renderers.UnreadableValue) for v in first[3:])
    assert [r[3] for r in rows[1:]] == [0, 2, 3]


def test_ops_of_a_ring_whose_state_cannot_be_read_is_one_unreadable_row():
    def broken(ring):
        raise exceptions.InvalidAddressException("kernel", 1, "freed")

    (row,) = ops_rows(plugin_ring(ring_state=broken))
    assert len(row) == len(io_uring.Rings._HEAD) + len(io_uring.Ops._columns)
    assert all(isinstance(v, renderers.UnreadableValue) for v in row[3:])


def test_files_rows_flag_a_file_that_no_fd_table_holds():
    """Hidden = the slot's file is in no process's fd table; the others say which."""
    rows = populate(make_plugin(io_uring.Files, [plugin_ring()]))
    by_slot = {row[3]: row for row in rows}
    assert by_slot[0][4:] == (
        io_uring.format_hints.Hex(0xA0),
        "file",
        "/f/a0",
        "5:3, 6:4",
        False,
    )
    unreadable_row = by_slot[2]
    assert all(isinstance(v, renderers.UnreadableValue) for v in unreadable_row[4:])
    hidden = by_slot[3]
    assert hidden[4:8] == (io_uring.format_hints.Hex(0xB0), "file", "/f/b0", hidden[7])
    assert isinstance(hidden[7], renderers.NotAvailableValue) and hidden[8] is True


def ops_ring(entries, cqes, **state):
    return plugin_ring(
        ring_state=lambda r: make_state(cq_tail=len(cqes), cached_sq_head=2, **state),
        sqes=lambda r, st: iter(entries),
        cqes=lambda st: cqes,
        describe_sqe=lambda task, e: f"op{e.opcode}",
    )


def ops_rows(ring):
    return populate(make_plugin(io_uring.Ops, [ring]))


def test_ops_rows_are_typed_with_the_result_and_how_it_was_found():
    entries = [
        make_sqe("OPENAT", seq=2, age=None, fd=-100, user_data=3, flags=0b100),
        make_sqe("CLOSE", seq=1, age=0, fd=5, user_data=2),
        make_sqe("SOCKET", seq=0, age=1, fd=2, user_data=1),
    ]
    cqes = {0: (1, 6, 0), 1: (2, -9, 0)}
    rows = ops_rows(ops_ring(entries, cqes))
    names = [n for n, _ in io_uring.Rings._HEAD + io_uring.Ops._columns]
    got = [dict(zip(names, row)) for row in rows]
    assert [g["Op"] for g in got] == ["OPENAT", "CLOSE", "SOCKET"]
    assert (
        isinstance(got[0]["Age"], renderers.NotAvailableValue)
        and got[0]["Completion"] == "not submitted"
    )
    assert isinstance(got[0]["Result"], renderers.NotAvailableValue)
    assert got[0]["Fd"] == -100 and got[0]["SQE flags"] == "IO_LINK"
    assert (got[1]["Age"], got[1]["Fd"], got[1]["Result"], got[1]["Completion"]) == (
        0,
        5,
        -9,
        "user_data",
    )
    # SOCKET's fd field is the domain, not a descriptor
    assert isinstance(got[2]["Fd"], renderers.NotAvailableValue)
    assert (got[2]["Age"], got[2]["Result"]) == (1, 6)
    assert got[1]["Arguments"] == f"op{io_uring.OPCODES.index('CLOSE')}"


def test_ops_rows_of_a_ring_whose_cq_cannot_be_read_still_list_the_sqes():
    def broken(st):
        raise exceptions.InvalidAddressException("kernel", 1, "cq")

    entries = [make_sqe("READ", seq=0, age=0, user_data=1)]
    ring = ops_ring(entries, {})
    ring.core.reader.cqes = broken
    (row,) = ops_rows(ring)
    assert isinstance(row[-3], renderers.UnreadableValue) and row[-2] == "CQ unreadable"


def test_ops_rows_of_a_ring_with_mixed_size_entries_are_not_decoded():
    ring = ops_ring([], {}, flags=io_uring.SETUP["SQE_MIXED"])
    (row,) = ops_rows(ring)
    assert all(isinstance(v, renderers.NotAvailableValue) for v in row[3:])


def test_personalities_rows_show_the_creds_next_to_the_tasks_own():
    creds = {
        "task": (65534, 65534, 65534, 65534, 0),
        "root": (0, 0, 0, 0, 0x1FFFFFFFFFF),
    }
    ring = plugin_ring(
        personalities=lambda r: iter([(1, "root"), (2, "bad")]),
        cred_ids=lambda cred: (
            creds[cred]
            if cred in creds
            else (_ for _ in ()).throw(
                exceptions.InvalidAddressException("kernel", 1, "x")
            )
        ),
    )
    ring.task.cred = "task"
    first, second = populate(make_plugin(io_uring.Personalities, [ring]))
    hex_ = io_uring.format_hints.Hex
    assert first[3:] == (
        1,
        0,
        0,
        0,
        hex_(0x1FFFFFFFFFF),
        65534,
        65534,
        65534,
        hex_(0),
        True,
    )
    assert second[3] == 2
    assert all(
        isinstance(v, renderers.UnreadableValue) for v in second[4:8] + second[12:]
    )


class FakeImu:
    ubuf = 0x7F0000001000
    nr_bvecs = 2


def buffers_ring(**core_attrs):
    attrs = dict(
        buffers=lambda r: iter([(0, FakeImu()), (1, None), (2, FakeImu())]),
        buffer_bytes=lambda imu, limit: (
            b"abc\x00\x00" if limit else b"abc\x00\x00DUMP",
            7,
            4096,
        ),
    )
    attrs.update(core_attrs)
    return plugin_ring(**attrs)


def test_buffers_rows_preview_the_start_and_say_what_is_missing():
    ring = buffers_ring()
    rows = populate(make_plugin(io_uring.Buffers, [ring]))
    assert [r[3] for r in rows] == [0, 1, 2]
    hex_ = io_uring.format_hints.Hex
    assert rows[0][4:] == (hex_(0x7F0000001000), 4096, 2, "abc", 7, rows[0][-1])
    assert isinstance(rows[0][-1], renderers.NotAvailableValue)  # no --dump: no file
    assert all(isinstance(v, renderers.UnreadableValue) for v in rows[1][4:])


def test_buffers_dump_writes_each_whole_buffer_to_a_named_file():
    ring = buffers_ring()
    plugin = make_plugin(io_uring.Buffers, [ring], dump=True)
    rows = populate(plugin)
    name = f"io_uring.7.{ring.addr:#x}.buf0.dmp"
    assert rows[0][-1] == name and rows[0][-3] == "abc.." + "DUMP"
    assert plugin.sink.files[name] == b"abc\x00\x00DUMP"
    assert len(plugin.sink.files) == 2


def test_buffers_whose_contents_cannot_be_read_are_unreadable_rows():
    def broken(imu, limit):
        raise exceptions.InvalidAddressException("kernel", 1, "pages")

    ring = buffers_ring(buffer_bytes=broken)
    rows = populate(make_plugin(io_uring.Buffers, [ring]))
    assert all(
        all(isinstance(v, renderers.UnreadableValue) for v in r[4:]) for r in rows
    )


def test_list_rings_builds_the_core_and_walks_it(monkeypatch):
    seen = []

    class FakeCore:
        def __init__(self, context, kernel_name):
            seen.append((context, kernel_name))

        def find_rings(self, filter_func):
            return iter([filter_func])

    monkeypatch.setattr(io_uring, "IoUringCore", FakeCore)
    keep_all = lambda task: False  # noqa: E731
    assert list(io_uring.Rings.list_rings("context", "kernel", keep_all)) == [keep_all]
    assert seen == [("context", "kernel")]
