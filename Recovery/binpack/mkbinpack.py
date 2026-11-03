#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-EPSL-1.1
#
# Builds the recovery binpack: Shared/Recovery/binpack.zip, unpacked by the TWRP
# terminal into ~/Library/TWRP/opt/procursus (the roothide jbroot of the recovery).
#
# A minimal Darwin bootstrap with the GNU userland people expect (bash, coreutils,
# grep, sed, findutils, diffutils, tar, ncurses tools, vi), taken from the emexOS
# procursus bootstrap: dpkg packages are selected by their .list files, the dylib
# closure is computed from the Mach-O load commands, documentation is dropped.
# The vroot libraries the bootstrap binaries link (libvrootapi -> libvroot ->
# libroothide) come from an emexOS build; roothideinit.dylib is NOT shipped, the
# recovery symlinks it to its own runtime patch (librecoveryrtpatch).
#
# Extra packages come as .deb files from the roothide procursus repo
# (https://roothide.github.io/procursus, iphoneos-arm64e/1900): --debs takes a
# directory of them, every file they install is added (they win over the
# bootstrap), and the dylib closure then warns about any library still missing
# (fetch that package too). data.tar.zst needs the zstd tool.
#
# Stdlib only (plus zstd for .deb), runs on macOS and Linux:
#   mkbinpack.py --bootstrap ../emexOS/bootstrap \
#                --vroot-libs ../emexOS/.rompkg/ROM/binpack/usr/lib \
#                [--debs Recovery/binpack/debs] \
#                --output Shared/Recovery/binpack.zip

import argparse
import io
import lzma
import os
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

PACKAGES = [
    "base", "profile.d", "bash", "dash", "coreutils", "grep", "sed", "findutils",
    "diffutils", "tar", "ncurses-bin", "debianutils", "vi", "file-cmds", "shell-cmds",
    "darwintools", "roothide", "ca-certificates",
]

# from packages too big to take whole
EXTRA_FILES = [
    "usr/bin/getconf", "usr/bin/pagesize", "usr/bin/hostinfo", "usr/bin/arch", "usr/bin/machine",
    "usr/sbin/sysctl",
]

TERMINFO = [
    "x/xterm-256color", "x/xterm", "x/xterm-color", "v/vt100", "v/vt102", "v/vt220", "a/ansi",
    "l/linux", "d/dumb", "s/screen", "s/screen-256color", "t/tmux", "t/tmux-256color",
]

VROOT_LIBS = ["libvrootapi.dylib", "libvroot.dylib", "libroothide.dylib"]

# files changed on the way into the binpack: (old, new) replacements, each must match
EDITS = {
    # the recovery's user has no passwd entry a guest can look up, so nano cannot name its lock
    # files ("Couldn't determine my identity for lock file")
    "etc/nanorc": [("\nset locking\n", "\n# set locking\n")],
}

DROP_PREFIXES = (
    "usr/share/man/", "usr/share/doc/", "usr/share/info/", "usr/share/locale/", "usr/include/",
    "usr/lib/pkgconfig/", "usr/share/bash-completion/", "usr/share/zsh/", "usr/lib/bash/",
    "usr/share/terminfo/", "etc/pam.d/",
)
# provided by the recovery itself
DROP_FILES = {"usr/lib/roothideinit.dylib", "usr/lib/libroothide.dylib", "usr/lib/libvroot.dylib", "usr/lib/libvrootapi.dylib"}

DIRECTORIES = ["tmp", "var/tmp", "var/root", "var/run", "var/run/pty", "var/log", "var/lib", "etc/profile.d", "usr/local/bin"]

LINKS = {
    "usr/bin/vi": "ex-vi",
    "usr/bin/ex": "ex-vi",
    "usr/bin/view": "ex-vi",
    # unrar's postinst picks it with update-alternatives
    "usr/bin/unrar": "unrar-nonfree",
}

PROFILE_TWRP = """\
# TWRP terminal (Nyxian recovery)
export TERM="${TERM:-xterm-256color}"
export PS1='\\w # '
# no LANG/LC_*: iOS has no C.UTF-8, and readline 8.2 (_rl_init_locale) does
# strlen(setlocale(LC_CTYPE, $LANG)) without a NULL check -> crash at the next prompt
if [ -z "$NX_RECOVERY_MOTD_SHOWN" ] && [ -t 1 ]; then
    export NX_RECOVERY_MOTD_SHOWN=1
    echo "Nyxian recovery shell. / (and ~) is the binpack, /rootfs is the bootloader's container."
fi
"""

LC_REQ_DYLD = 0x80000000
LOAD_COMMANDS = {0xC, 0xD | 0, 0x18 | LC_REQ_DYLD, 0x1F | LC_REQ_DYLD, 0x23 | LC_REQ_DYLD, 0x20 | LC_REQ_DYLD}
LC_ID_DYLIB = 0xD
LC_RPATH = 0x1C | LC_REQ_DYLD


def macho_dylibs(path):
    """dependent dylib paths of a (fat) Mach-O, None if it is not one"""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    if len(data) < 32:
        return None
    magic = struct.unpack(">I", data[:4])[0]
    offsets = []
    if magic in (0xCAFEBABE, 0xCAFEBABF):
        count = struct.unpack(">I", data[4:8])[0]
        wide = magic == 0xCAFEBABF
        for i in range(count):
            if wide:
                cpu, _, off = struct.unpack(">IIQ", data[8 + i * 32:8 + i * 32 + 16])
            else:
                cpu, _, off = struct.unpack(">III", data[8 + i * 20:8 + i * 20 + 12])
            offsets.append(off)
    elif struct.unpack("<I", data[:4])[0] == 0xFEEDFACF:
        offsets = [0]
    else:
        return None
    deps = set()
    for base in offsets:
        if struct.unpack("<I", data[base:base + 4])[0] != 0xFEEDFACF:
            continue
        ncmds = struct.unpack("<I", data[base + 16:base + 20])[0]
        p = base + 32
        for _ in range(ncmds):
            cmd, size = struct.unpack("<II", data[p:p + 8])
            if cmd in LOAD_COMMANDS and cmd != LC_ID_DYLIB:
                name_off = struct.unpack("<I", data[p + 8:p + 12])[0]
                deps.add(data[p + name_off:p + size].split(b"\0")[0].decode())
            p += size
    return deps


def dep_to_relative(dep):
    """map a load command path to a path inside the binpack, None for system libraries"""
    for prefix in ("@loader_path/.jbroot/", "@executable_path/.jbroot/"):
        if dep.startswith(prefix):
            return dep[len(prefix):]
    if dep.startswith("@rpath/"):
        # every bootstrap binary has LC_RPATH @loader_path/.jbroot/usr/lib
        return "usr/lib/" + dep[len("@rpath/"):]
    return None


def deb_members(path):
    """the members of a .deb (an ar archive) as {name: bytes}"""
    with open(path, "rb") as f:
        data = f.read()
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("%s is not a .deb" % path)
    members, offset = {}, 8
    while offset + 60 <= len(data):
        header = data[offset:offset + 60]
        name = header[0:16].decode("ascii", "replace").strip().rstrip("/")
        size = int(header[48:58].decode("ascii").strip())
        members[name] = data[offset + 60:offset + 60 + size]
        offset += 60 + size + (size & 1)
    return members


def deb_extract(path, destination):
    """unpacks a .deb's data.tar.* into destination"""
    for name, payload in deb_members(path).items():
        if not name.startswith("data.tar"):
            continue
        if name.endswith(".zst"):
            payload = subprocess.run(["zstd", "-dc"], input=payload, stdout=subprocess.PIPE, check=True).stdout
        elif name.endswith((".xz", ".lzma")):
            payload = lzma.decompress(payload)
        mode = "r:gz" if name.endswith(".gz") else ("r:bz2" if name.endswith(".bz2") else "r:")
        with tarfile.open(fileobj=io.BytesIO(payload), mode=mode) as tar:
            for member in tar.getmembers():
                rel = os.path.normpath(member.name).lstrip("./")
                if not rel or rel.startswith(".."):
                    continue
                full = os.path.join(destination, rel)
                if member.isdir():
                    os.makedirs(full, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(full), exist_ok=True)
                if os.path.lexists(full):
                    os.remove(full)
                if member.issym():
                    os.symlink(member.linkname, full)
                elif member.islnk():
                    shutil.copyfile(os.path.join(destination, os.path.normpath(member.linkname).lstrip("./")), full)
                    os.chmod(full, member.mode & 0o7777)
                elif member.isfile():
                    with tar.extractfile(member) as src, open(full, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    os.chmod(full, member.mode & 0o7777)
        return
    raise ValueError("%s has no data.tar" % path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bootstrap", required=True)
    parser.add_argument("--vroot-libs", required=True)
    parser.add_argument("--debs", help="directory of extra roothide procursus .deb packages")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    bootstrap = os.path.abspath(args.bootstrap)
    debroot = tempfile.mkdtemp(prefix="binpack-debs-")
    deb_files = []
    if args.debs:
        for name in sorted(os.listdir(args.debs)):
            if name.endswith(".deb"):
                deb_extract(os.path.join(args.debs, name), debroot)
                print("deb: " + name)
        for d, _, names in os.walk(debroot):
            for name in names:
                deb_files.append(os.path.relpath(os.path.join(d, name), debroot))

    def src(rel):
        """where a binpack path comes from: an extra .deb wins over the bootstrap"""
        rel = rel.strip("/")
        candidate = os.path.join(debroot, rel)
        if os.path.lexists(candidate):
            return candidate
        return os.path.join(bootstrap, rel)

    root = bootstrap
    files = set()
    extra_dirs = set()

    def add(rel):
        rel = rel.strip("/")
        if not rel or rel in DROP_FILES or rel.startswith(DROP_PREFIXES):
            return
        full = src(rel)
        if not os.path.lexists(full):
            return
        if rel in files:
            return
        if os.path.isdir(full) and not os.path.islink(full):
            extra_dirs.add(rel)
            return
        files.add(rel)
        if os.path.islink(full):
            target = os.readlink(full)
            # keep links that stay inside the binpack alive
            resolved = os.path.normpath(os.path.join(os.path.dirname(rel), target)) if not target.startswith("/") else target.strip("/")
            if not resolved.startswith("..") and not target.startswith("/rootfs"):
                add(resolved)
        # every directory in the path keeps its .jbroot link
        d = os.path.dirname(rel)
        while d:
            jb = os.path.join(d, ".jbroot")
            if os.path.islink(src(jb)):
                files.add(jb)
            d = os.path.dirname(d)

    for package in PACKAGES:
        listing = os.path.join(root, "Library/dpkg/info", package + ".list")
        if not os.path.exists(listing):
            print("warning: no package " + package, file=sys.stderr)
            continue
        for line in open(listing, encoding="utf-8", errors="replace"):
            path = line.rstrip("\n").split(" -> ")[0]
            full = os.path.join(root, path.strip("/"))
            if os.path.isdir(full) and not os.path.islink(full):
                continue
            add(path)
    for extra in EXTRA_FILES:
        add(extra)
    for rel in deb_files:
        add(rel)
    for entry in TERMINFO:
        rel = "usr/share/terminfo/" + entry
        if os.path.lexists(os.path.join(root, rel)):
            files.add(rel)

    # dylib closure
    pending = list(files)
    seen = set()
    while pending:
        rel = pending.pop()
        if rel in seen:
            continue
        seen.add(rel)
        full = src(rel)
        if os.path.islink(full) or not os.path.isfile(full):
            continue
        deps = macho_dylibs(full)
        if not deps:
            continue
        for dep in deps:
            target = dep_to_relative(dep)
            if target is None or os.path.basename(target) in VROOT_LIBS or target in DROP_FILES:
                continue
            if not os.path.lexists(src(target)):
                print("warning: %s needs %s, not in the bootstrap or the debs" % (rel, dep), file=sys.stderr)
                continue
            before = set(files)
            add(target)
            pending.extend(files - before)

    vroot_dir = os.path.abspath(args.vroot_libs)
    for lib in VROOT_LIBS:
        if not os.path.isfile(os.path.join(vroot_dir, lib)):
            sys.exit("error: %s missing in %s (build emexOS first)" % (lib, vroot_dir))

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    stamp = time.localtime(time.time())[:6]
    total = 0
    with zipfile.ZipFile(args.output, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        def put_dir(rel):
            info = zipfile.ZipInfo(rel.rstrip("/") + "/", stamp)
            info.create_system = 3
            info.external_attr = ((stat.S_IFDIR | (0o1777 if rel in ("tmp",) else 0o755)) << 16) | 0x10
            zf.writestr(info, b"")

        def put_link(rel, target):
            info = zipfile.ZipInfo(rel, stamp)
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, target.encode())

        def put_file(rel, data, mode):
            info = zipfile.ZipInfo(rel, stamp)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | mode) << 16
            zf.writestr(info, data)

        directories = set(DIRECTORIES) | extra_dirs
        for rel in files:
            d = os.path.dirname(rel)
            while d:
                directories.add(d)
                d = os.path.dirname(d)
        for d in sorted(directories):
            put_dir(d)

        put_link(".jbroot", ".")
        # a directory with Mach-Os needs its .jbroot link (@loader_path/.jbroot), debs may add new ones
        jbroot_links = set(rel for rel in files if os.path.basename(rel) == ".jbroot")
        for rel in sorted(files):
            d = os.path.dirname(rel)
            jb = os.path.join(d, ".jbroot")
            if d and jb not in jbroot_links and not os.path.islink(src(rel)) and os.path.isfile(src(rel)) and macho_dylibs(src(rel)) is not None:
                put_link(jb, "../" * (d.count("/") + 1) + ".jbroot")
                jbroot_links.add(jb)
        for rel in sorted(files):
            full = src(rel)
            if os.path.islink(full):
                put_link(rel, os.readlink(full))
            else:
                mode = os.stat(full).st_mode & 0o7777
                if mode & 0o100:
                    mode |= 0o755
                with open(full, "rb") as f:
                    data = f.read()
                for before, after in EDITS.get(rel, []):
                    if before.encode() not in data:
                        sys.exit("error: %s no longer contains %r" % (rel, before))
                    data = data.replace(before.encode(), after.encode())
                total += len(data)
                put_file(rel, data, (mode | 0o644) if mode else 0o644)
        for rel, target in LINKS.items():
            if rel not in files:
                put_link(rel, target)
        if "bin/sh" not in files and "usr/bin/dash" in files:
            put_link("bin/sh", "../usr/bin/dash")
        for lib in VROOT_LIBS:
            with open(os.path.join(vroot_dir, lib), "rb") as f:
                data = f.read()
            total += len(data)
            put_file("usr/lib/" + lib, data, 0o755)
        put_file("etc/profile.d/twrp.sh", PROFILE_TWRP.encode(), 0o644)

    shutil.rmtree(debroot, ignore_errors=True)
    print("%s: %d entries, %.1f MiB uncompressed, %.1f MiB zipped" % (
        args.output, len(files), total / 1048576.0, os.path.getsize(args.output) / 1048576.0))


if __name__ == "__main__":
    main()
