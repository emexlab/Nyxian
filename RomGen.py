#!/usr/bin/env python3
"""
RomGen.py: Nyxian ROM templates, ROM signing keys and signed ROM ZIPs.

    RomGen.py generate <nyxian-root> <out-dir> [--identifier com.vendor.rom] [--name "My ROM"]
        bakes a ROM template from a Nyxian checkout (the kernel surface, the
        window server, an NXSlotMain and a Hello app);
        `make` in it builds the signed rom.zip

    RomGen.py genkey --name myrom
        creates your key pair: ~/.config/nyxian/romkey/myrom.key.pem (private,
        stays with you) and myrom.pub.pem (public: register it with your
        NXRomIdentifier(s) on developer.emexlabs.org to get it into the TrustStore)

    RomGen.py sign MyROM.zip --key ~/.config/nyxian/romkey/myrom.key.pem
        checks the ROM's manifest, puts the signed file list (NXRomFiles.plist) in
        and appends the release signature (NXROM001)

    RomGen.py verify MyROM.zip [--public myrom.pub.pem] [--truststore truststore.plist|online]
        checks the signature; with the TrustStore also whether Nyxian trusts
        your key for this ROM

    RomGen.py info MyROM.zip | KEY.pem       manifest and signer / key ID
    RomGen.py prove --key myrom.key.pem 'CODE'
        signs the code the Developer Portal (developer.emexlabs.org) shows when
        you register a key, to prove the key is yours; the key stays here
    RomGen.py public myrom.key.pem           the public key again, if you lost it
    RomGen.py digest MyROM.zip                the release's digest: sign it on your key's Developer Portal page,
                                              so devices get install tickets for it (bootloader 0.11.6.4+)

Nyxian only boots a ROM whose ZIP carries a release signature by a key in
emexLabs' TrustStore. A ROM ZIP holds one top-level directory (its name does
not matter) with manifest.plist: NXRomManifestVersion, NXRomIdentifier
(reverse DNS), NXRomName, NXRomVersion, NXRomMinimumNyxianVersion,
NXRomExecutable and NXRomSecurityVersion (a positive integer; raise it for
every release, Nyxian refuses to go back to a lower one).

The signed file list (NXRomFiles.plist, next to manifest.plist) holds every file,
folder and symlink of the ROM with its hash, signed with the same key. Nyxian
re-signs the ROM's Mach-O files with the user's certificate when it flashes it,
and checks at every boot that nothing but their code signature changed: a slot
with anything else in it doesn't boot (bootloader 0.11.6.4+). The hash of a
Mach-O leaves out exactly what re-signing changes (see file_hash), so every
Mach-O needs a code signature already; sign leaves unsigned ones signed ad hoc
(codesign, on macOS).

Needs Python 3 and the openssl command line.
"""
import argparse
import hashlib
import os
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from collections import defaultdict
from pathlib import Path

GEN_ROM_REV = '2026-11-06-ROMGEN-4'
ARCHIVE_DOMAIN = b'NXROM-ARCHIVE-v1\0'
FILES_DOMAIN = b'NXROM-FILES-v1\0'
FILES_NAME = 'NXRomFiles.plist'
STORE_DOMAIN = b'NXROM-TRUSTSTORE-v1\0'
FOOTER = struct.Struct('<72sQI8s')
MAGIC = b'NXROM001'
SPKI_PREFIX = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200')
KEY_DIR = Path.home() / '.config/nyxian/romkey'
TRUSTSTORE_URL = 'https://emexlabs.org/switzach/truststore/truststore.plist'
ROOT_KEYS = [bytes.fromhex(
    '04989624aca8eebf568360d73c8977ec44577007cc3f5a9f2bc3fefefd17c5019b'
    '9b4e2ea92658c35a2ffac572ec9c558e9de49267d5e6a001609a2e17d0a8291d')]


def fail(message):
    raise SystemExit(f'RomGen: {message}')


def identifier_valid(value):
    return (isinstance(value, str) and 0 < len(value) <= 255 and re.fullmatch(r'[A-Za-z0-9._-]+', value) is not None
            and len(value.split('.')) >= 2 and all(value.split('.')))


def key_id(raw):
    return hashlib.sha256(raw).hexdigest()[:16]


def openssl(*args, data=None):
    result = subprocess.run(['openssl', *args], input=data, capture_output=True)
    if result.returncode:
        fail(f'openssl {args[0]}: {result.stderr.decode(errors="replace").strip() or "failed"}')
    return result.stdout


def raw_public_key(path, private=False):
    data = Path(path).read_bytes()
    form = 'PEM' if data.lstrip().startswith(b'-----') else 'DER'
    args = ['pkey', '-in', str(path), '-inform', form, '-pubout', '-outform', 'DER']
    if not private and b'PRIVATE KEY' not in data:
        args.insert(1, '-pubin')
    der = openssl(*args)
    if not der.startswith(SPKI_PREFIX) or len(der) != len(SPKI_PREFIX) + 65:
        fail(f'{path} is not a P-256 (prime256v1) key')
    return der[len(SPKI_PREFIX):]


def public_pem(raw):
    with tempfile.NamedTemporaryFile(suffix='.der') as der:
        der.write(SPKI_PREFIX + raw)
        der.flush()
        return openssl('pkey', '-pubin', '-inform', 'DER', '-in', der.name, '-outform', 'PEM')


def verify_digest(raw, digest, signature):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / 'key.der').write_bytes(SPKI_PREFIX + raw)
        (root / 'signature').write_bytes(signature)
        return subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-keyform', 'DER',
                               '-inkey', str(root / 'key.der'), '-sigfile', str(root / 'signature'),
                               '-pkeyopt', 'digest:sha256'], input=digest, capture_output=True).returncode == 0


def read_footer(path):
    size = path.stat().st_size
    if size >= FOOTER.size:
        with path.open('rb') as source:
            source.seek(-FOOTER.size, 2)
            signature, length, count, magic = FOOTER.unpack(source.read(FOOTER.size))
        if magic == MAGIC:
            if length != size - FOOTER.size or not 8 <= count <= 72 or any(signature[count:]):
                fail(f'{path.name} has a malformed release signature footer')
            return length, signature[:count]
    return size, None


def archive_digest(path, length):
    digest = hashlib.sha256(ARCHIVE_DOMAIN)
    with path.open('rb') as source:
        while length:
            data = source.read(min(length, 1 << 20))
            if not data:
                fail('the archive is truncated')
            digest.update(data)
            length -= len(data)
    return digest.digest()


def read_manifest(path):
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        fail(f'{path.name} is not a ZIP archive')
    with archive:
        names = [name for name in archive.namelist() if name and not name.startswith('__MACOSX/')]
        tops = {name.split('/', 1)[0] for name in names}
        if archive.testzip() is not None:
            fail(f'{path.name} is a corrupt ZIP')
        if len(tops) != 1 or not any('/' in name for name in names):
            fail('a ROM ZIP holds exactly one top-level directory (Nyxian extracts what is inside it)')
        top = tops.pop()
        try:
            manifest = plistlib.loads(archive.read(f'{top}/manifest.plist'))
        except KeyError:
            fail(f'{top}/manifest.plist is missing')
        problems = []
        if type(manifest.get('NXRomManifestVersion')) is not int:
            problems.append('NXRomManifestVersion must be an integer')
        for key in ('NXRomName', 'NXRomVersion', 'NXRomMinimumNyxianVersion', 'NXRomExecutable'):
            if not isinstance(manifest.get(key), str) or not manifest[key]:
                problems.append(f'{key} must be a string')
        if not identifier_valid(manifest.get('NXRomIdentifier')):
            problems.append('NXRomIdentifier must be reverse DNS (letters, digits, ".", "-", "_"), like com.vendor.rom')
        security = manifest.get('NXRomSecurityVersion')
        if type(security) is not int or not 1 <= security < (1 << 63):
            problems.append('NXRomSecurityVersion must be a positive integer (raise it for every release)')
        executable = manifest.get('NXRomExecutable')
        if isinstance(executable, str) and f'{top}/{executable}' not in names:
            problems.append(f'NXRomExecutable {executable} is not in the archive')
        if problems:
            fail('manifest.plist: ' + '; '.join(problems))
        return manifest


def read_top(archive):
    return {name.split('/', 1)[0] for name in archive.namelist() if name and not name.startswith('__MACOSX/')}.pop()


def load_truststore(source):
    if source == 'online':
        import urllib.request
        try:
            with urllib.request.urlopen(TRUSTSTORE_URL, timeout=30) as response:
                data = response.read(1 << 20)
        except OSError as error:
            fail(f'could not download {TRUSTSTORE_URL}: {error}')
    else:
        data = Path(source).read_bytes()
    envelope = plistlib.loads(data)
    if not isinstance(envelope, dict) or envelope.get('format') != 1:
        fail('not a TrustStore')
    root = next((key for key in ROOT_KEYS if hashlib.sha256(key).digest() == envelope.get('rootKey')), None)
    if root is None or not verify_digest(root, hashlib.sha256(STORE_DOMAIN + envelope.get('payload', b'')).digest(),
                                         envelope.get('signature', b'')):
        fail('the TrustStore is not signed by an emexLabs root key')
    return plistlib.loads(envelope['payload'])


# MARK: the signed file list (NXRomFiles.plist): the hash of every file, the same as
# Nyxian/LindChain/Utils/NXROMFileHash.h computes it. Keep the two equal.
MACHO_DOMAIN = b'NXROM-MACHO-v1\0'
FAT_DOMAIN = b'NXROM-FAT-v1\0'
LC_SEGMENT_64, LC_CODE_SIGNATURE, LC_ID_DYLIB, LC_NX_LOADER = 0x19, 0x1d, 0x0d, 0x114514
MH_EXECUTE, MH_DYLIB, MH_NO_REEXPORTED_DYLIBS, MH_PIE = 2, 6, 0x100000, 0x200000
LIBCPP = b'/usr/lib/libc++.1.dylib\0'
ZEROFILL = (0x1, 0xc, 0x12)


class MachOError(ValueError):
    pass


def file_kind(data):
    """'macho', 'unsupported' (32-bit or big endian Mach-O) or 'plain'"""
    if len(data) < 4:
        return 'plain'
    magic = struct.unpack_from('<I', data)[0]
    if magic in (0xfeedfacf, 0xbebafeca, 0xbfbafeca):
        return 'macho'
    if magic in (0xfeedface, 0xcefaedfe, 0xcffaedfe, 0xcafebabe, 0xcafebabf):
        return 'unsupported'
    return 'plain'


def _inserted_id_dylib(command, name):
    size = 24 + ((len(name) + 1 + 7) & ~7)
    return (len(command) == size and struct.unpack_from('<IIII', command, 8) == (24, 2, 0x10000, 0x10000)
            and command[24:24 + len(name)] == name and not any(command[24 + len(name):]))


def _loader_command(command):
    if len(command) < 24:
        return False
    offset = struct.unpack_from('<I', command, 8)[0]
    return 24 <= offset < len(command) and len(command) - offset >= len(LIBCPP) and command[offset:offset + len(LIBCPP)] == LIBCPP


def _thin(data, name):
    if len(data) < 32 or struct.unpack_from('<I', data)[0] != 0xfeedfacf:
        raise MachOError('not a 64-bit Mach-O')
    filetype, ncmds, sizeofcmds, flags = struct.unpack_from('<IIII', data, 12)
    if ncmds == 0 or sizeofcmds > len(data) - 32 or sizeofcmds > 1 << 24:
        raise MachOError('malformed load commands')
    end, offset, commands = 32 + sizeofcmds, 32, []
    for _ in range(ncmds):
        if end - offset < 8:
            raise MachOError('malformed load commands')
        cmd, size = struct.unpack_from('<II', data, offset)
        if size < 8 or size % 8 or size > end - offset:
            raise MachOError('malformed load commands')
        if cmd == LC_SEGMENT_64 and (size < 72 or struct.unpack_from('<I', data, offset + 64)[0] > (size - 72) // 80):
            raise MachOError('malformed segment')
        commands.append((cmd, offset, size))
        offset += size
    if offset != end:
        raise MachOError('malformed load commands')
    signatures = [(offset, size) for cmd, offset, size in commands if cmd == LC_CODE_SIGNATURE]
    if len(signatures) != 1:
        raise MachOError('more than one code signature' if signatures else 'no code signature (sign it ad hoc: codesign -s -)')
    if signatures[0][1] != 16:
        raise MachOError('malformed LC_CODE_SIGNATURE')
    dataoff = struct.unpack_from('<I', data, signatures[0][0] + 8)[0]
    if dataoff < end or dataoff > len(data):
        raise MachOError('the code signature lies outside the file')

    content = dataoff
    for cmd, offset, size in commands:
        if cmd != LC_SEGMENT_64:
            continue
        fileoff, filesize = struct.unpack_from('<QQ', data, offset + 40)
        if fileoff > 0 and filesize > 0:
            content = min(content, fileoff)
        for j in range(struct.unpack_from('<I', data, offset + 64)[0]):
            section = offset + 72 + 80 * j
            section_size = struct.unpack_from('<Q', data, section + 40)[0]
            section_offset = struct.unpack_from('<I', data, section + 48)[0]
            kind = struct.unpack_from('<I', data, section + 64)[0] & 0xff
            if section_offset > 0 and section_size > 0 and kind not in ZEROFILL:
                content = min(content, section_offset)
    if content < end:
        raise MachOError('the load commands overlap the code')
    if any(data[end:content]):
        raise MachOError('bytes between the load commands and the code')

    kept = bytearray()
    count = 0
    for index, (cmd, offset, size) in enumerate(commands):
        command = bytearray(data[offset:offset + size])
        if cmd == LC_ID_DYLIB and index == 0 and _inserted_id_dylib(command, name):
            continue
        if cmd == LC_NX_LOADER:
            if not _loader_command(command):
                raise MachOError("a LiveContainer loader command that doesn't load libc++")
            continue
        if cmd == LC_SEGMENT_64:
            segment = bytes(command[8:24]).split(b'\0', 1)[0]
            if segment == b'__PAGEZERO':
                command[24:40] = bytes(16)
            elif segment == b'__LINKEDIT':
                command[32:40] = bytes(8)
                command[48:56] = bytes(8)
        elif cmd == LC_CODE_SIGNATURE:
            command[12:16] = bytes(4)
        kept += command
        count += 1
    header = bytearray(data[:32])
    struct.pack_into('<IIII', header, 12, MH_DYLIB if filetype in (MH_EXECUTE, MH_DYLIB) else filetype, count, len(kept),
                     flags & ~(MH_NO_REEXPORTED_DYLIBS | MH_PIE))
    return hashlib.sha256(MACHO_DOMAIN + bytes(header) + bytes(kept) + data[content:dataoff]).digest()


def file_hash(data, name):
    """the file's hash in NXRomFiles.plist; name is its file name. MachOError for a Mach-O the list can't take"""
    data = bytes(data)
    name = name.encode() if isinstance(name, str) else name
    kind = file_kind(data)
    if kind == 'unsupported':
        raise MachOError('a 32-bit or big endian Mach-O')
    if kind == 'plain':
        return hashlib.sha256(data).digest()
    if struct.unpack_from('<I', data)[0] == 0xfeedfacf:
        return _thin(data, name)
    wide = struct.unpack_from('<I', data)[0] == 0xbfbafeca
    if len(data) < 8:
        raise MachOError('malformed fat header')
    slices = struct.unpack_from('>I', data, 4)[0]
    entry = 32 if wide else 20
    if not 0 < slices <= 16 or 8 + entry * slices > len(data):
        raise MachOError('malformed fat header')
    digest = hashlib.sha256(FAT_DOMAIN + data[4:8])
    for i in range(slices):
        arch = 8 + entry * i
        offset, length = struct.unpack_from('>QQ' if wide else '>II', data, arch + 8)
        if offset > len(data) or length > len(data) - offset:
            raise MachOError('a fat slice lies outside the file')
        digest.update(data[arch:arch + 8] + _thin(data[offset:offset + length], name))
    return digest.digest()


def nxt2_plist(data):
    """the entitlements plist of the NXT2 blob at the end of a file, None without one; MachOError for a broken one"""
    if len(data) < 8:
        return None
    if data[-4:] == b'NXTR':
        raise MachOError('an old NXTR blob')
    if data[-4:] != b'NXT2':
        return None
    length = struct.unpack_from('<I', data, len(data) - 8)[0]
    if length < 116 or length > 16384 or length + 8 > len(data):
        raise MachOError('a malformed NXT2 blob')
    blob = len(data) - 8 - length
    contained = struct.unpack_from('<Q', data, blob + 28)[0]
    if contained > length - 116:
        raise MachOError('a malformed NXT2 blob')
    return data[blob + 36:blob + 36 + contained]


def sign_digest(key, digest):
    signature = openssl('pkeyutl', '-sign', '-inkey', str(key), '-pkeyopt', 'digest:sha256', data=digest)
    if not 8 <= len(signature) <= 72:
        fail('openssl produced an invalid signature')
    return signature


def adhoc_sign(data, name, where):
    """a Mach-O without a code signature, signed ad hoc (Nyxian replaces the signature with the user's when it flashes)"""
    if shutil.which('codesign') is None:
        fail(f'{where} has no code signature: sign it ad hoc (codesign -s - FILE) or sign the ROM on macOS')
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / name
        path.write_bytes(data)
        result = subprocess.run(['codesign', '--sign', '-', '--force', str(path)], capture_output=True)
        if result.returncode:
            fail(f'codesign could not sign {where} ad hoc: {result.stderr.decode(errors="replace").strip()}')
        return path.read_bytes()


def archive_entries(archive, sign_unsigned=False):
    """(top, [(info, data)], files) of a ROM ZIP: what Nyxian extracts into a slot, the old file list and __MACOSX
    left out. files is what NXRomFiles.plist lists: {path: {type: file, hash} | {type: directory} | {type: symlink,
    target}}. With sign_unsigned, Mach-O files without a code signature come back signed ad hoc"""
    infos = [info for info in archive.infolist() if info.filename and not info.filename.startswith('__MACOSX/')]
    tops = {info.filename.split('/', 1)[0] for info in infos}
    if len(tops) != 1:
        fail('a ROM ZIP holds exactly one top-level directory')
    top = tops.pop()
    entries, files, directories, adhoc = [], {}, set(), []
    for info in infos:
        name = info.filename
        if name.startswith('/') or '\\' in name:
            fail(f'{name}: unsafe path in the ZIP')
        relative = name[len(top) + 1:].rstrip('/')
        if not relative:
            entries.append((info, None))
            continue
        parts = relative.split('/')
        if any(part in ('', '.', '..') for part in parts):
            fail(f'{name}: unsafe path in the ZIP')
        if relative == FILES_NAME:
            continue
        if relative in files or (relative in directories and not info.is_dir()):
            fail(f'{name} is in the ZIP twice')
        directories.update('/'.join(parts[:i]) for i in range(1, len(parts)))
        if info.is_dir():
            directories.add(relative)
            entries.append((info, None))
            continue
        data = archive.read(info)
        if (info.external_attr >> 16) & 0o170000 == 0o120000:
            files[relative] = {'type': 'symlink', 'target': data.decode('utf-8')}
        else:
            try:
                digest = file_hash(data, parts[-1])
            except MachOError as error:
                if not sign_unsigned or not str(error).startswith('no code signature'):
                    fail(f'{relative}: {error}')
                data = adhoc_sign(data, parts[-1], relative)
                adhoc.append(relative)
                try:
                    digest = file_hash(data, parts[-1])
                except MachOError as error:
                    fail(f'{relative}: {error}')
            files[relative] = {'type': 'file', 'hash': digest}
        entries.append((info, data))
    for directory in directories:
        if directory in files:
            fail(f'{top}/{directory} is a file and a folder at once')
        files[directory] = {'type': 'directory'}
    return top, entries, files, adhoc


def file_list_payload(manifest, files):
    return plistlib.dumps({'format': 1, 'identifier': manifest['NXRomIdentifier'], 'version': manifest['NXRomVersion'],
                           'securityVersion': manifest['NXRomSecurityVersion'], 'files': files},
                          fmt=plistlib.FMT_BINARY, sort_keys=True)


def write_listed_archive(source, target, manifest, key):
    """the ROM ZIP again, with unsigned Mach-O files signed ad hoc and the signed file list in it; returns (files,
    adhoc)"""
    with zipfile.ZipFile(source) as archive:
        top, entries, files, adhoc = archive_entries(archive, sign_unsigned=True)
        payload = file_list_payload(manifest, files)
        listing = plistlib.dumps({'format': 1, 'payload': payload,
                                  'signature': sign_digest(key, hashlib.sha256(FILES_DOMAIN + payload).digest())},
                                 fmt=plistlib.FMT_BINARY, sort_keys=True)
        with zipfile.ZipFile(target, 'w') as output:
            for info, data in entries:
                copy = zipfile.ZipInfo(info.filename, info.date_time)
                copy.external_attr, copy.create_system, copy.compress_type = info.external_attr, info.create_system, info.compress_type
                output.writestr(copy, b'' if data is None else data)
            entry = zipfile.ZipInfo(f'{top}/{FILES_NAME}', entries[0][0].date_time if entries else (1980, 1, 1, 0, 0, 0))
            entry.external_attr, entry.create_system, entry.compress_type = 0o100644 << 16, 3, zipfile.ZIP_DEFLATED
            output.writestr(entry, listing)
    return files, adhoc


def verify_file_list(path, raw, manifest):
    """the ZIP's NXRomFiles.plist: signed with raw, for this manifest, and every file in the ZIP matches it, the way
    Nyxian checks a slot. Returns how many entries it lists"""
    with zipfile.ZipFile(path) as archive:
        top, _, files, _ = archive_entries(archive)
        try:
            listing = plistlib.loads(archive.read(f'{top}/{FILES_NAME}'))
        except KeyError:
            fail(f'{path.name} has no signed file list ({FILES_NAME}): sign it with RomGen.py {GEN_ROM_REV} or newer')
    payload, signature = listing.get('payload'), listing.get('signature')
    if listing.get('format') != 1 or not isinstance(payload, bytes) or not isinstance(signature, bytes):
        fail(f'{FILES_NAME} is malformed')
    if not verify_digest(raw, hashlib.sha256(FILES_DOMAIN + payload).digest(), signature):
        fail(f'{FILES_NAME} is not signed with the key that signed the release')
    body = plistlib.loads(payload)
    if body.get('format') != 1 or body.get('identifier') != manifest['NXRomIdentifier'] \
            or body.get('version') != manifest['NXRomVersion'] or body.get('securityVersion') != manifest['NXRomSecurityVersion']:
        fail(f'{FILES_NAME} is for another release than manifest.plist')
    listed = body.get('files')
    if listed != files:
        missing = sorted(set(files) ^ set(listed or {}))
        changed = sorted(name for name in set(files) & set(listed or {}) if files[name] != listed[name])
        fail(f'the ZIP does not match {FILES_NAME}: ' + ', '.join((missing + changed)[:5]))
    return len(listed)


def command_genkey(args):
    directory = Path(args.out).expanduser()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    private = directory / f'{args.name}.key.pem'
    public = directory / f'{args.name}.pub.pem'
    if private.exists() or public.exists():
        fail(f'{private} exists already; a key is never overwritten (pick another --name)')
    old = os.umask(0o077)
    try:
        openssl('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', str(private))
    finally:
        os.umask(old)
    raw = raw_public_key(private, private=True)
    public.write_bytes(public_pem(raw))
    print(f'private key: {private}   (keep it secret and backed up, never share it)')
    print(f'public key:  {public}   (register it on developer.emexlabs.org)')
    print(f'key ID:      {key_id(raw)}')
    print('Register the public key with the NXRomIdentifier(s) it should sign on developer.emexlabs.org')
    print('(RomGen.py prove signs the code the portal shows); once it is in the TrustStore,')
    print(f'sign with: RomGen.py sign YourROM.zip --key {private}')


def command_public(args):
    raw = raw_public_key(args.key, private=True)
    sys.stdout.write(public_pem(raw).decode())
    print(f'key ID: {key_id(raw)}', file=sys.stderr)


PROOF_DOMAIN = b'NXROM-DEVPORTAL-PROOF-v1\0'


def command_prove(args):
    """ECDSA P-256 over SHA-256 of the domain and the portal's code, base64 DER: what the portal checks"""
    import base64
    key = Path(args.key).expanduser()
    if b'PRIVATE KEY' not in key.read_bytes():
        fail(f'{key} is not a private key: prove with NAME.key.pem, the key the .pub.pem belongs to')
    raw = raw_public_key(key, private=True)
    digest = hashlib.sha256(PROOF_DOMAIN + args.code.encode()).digest()
    with tempfile.NamedTemporaryFile() as source:
        source.write(digest)
        source.flush()
        signature = openssl('pkeyutl', '-sign', '-inkey', str(key), '-pkeyopt', 'digest:sha256', '-in', source.name)
    if not verify_digest(raw, digest, signature):
        fail('openssl made a signature that does not verify')
    print(base64.b64encode(signature).decode())
    print(f'key ID: {key_id(raw)}: paste the line above into the portal', file=sys.stderr)


def command_sign(args):
    path = Path(args.archive)
    manifest = read_manifest(path)
    key = Path(args.key).expanduser()
    if b'PRIVATE KEY' not in key.read_bytes():
        fail(f'{key} is not a private key')
    raw = raw_public_key(key, private=True)
    _, old = read_footer(path)
    descriptor, name = tempfile.mkstemp(prefix=path.name + '.', dir=path.parent)
    os.close(descriptor)
    temporary = Path(name)
    try:
        # the archive again, with the signed file list in it; then the release signature over all of it
        files, adhoc = write_listed_archive(path, temporary, manifest, key)
        length = temporary.stat().st_size
        digest = archive_digest(temporary, length)
        signature = sign_digest(key, digest)
        if not verify_digest(raw, digest, signature):
            fail('openssl produced an invalid signature')
        with temporary.open('ab') as target:
            target.write(FOOTER.pack(signature, length, len(signature), MAGIC))
            target.flush()
            os.fsync(target.fileno())
        signed_length, signed = read_footer(temporary)
        if signed_length != length or not verify_digest(raw, archive_digest(temporary, signed_length), signed):
            fail('the signed archive does not verify')
        with zipfile.ZipFile(temporary) as archive:
            if archive.testzip() is not None:
                fail('the signed ZIP is corrupt')
        verify_file_list(temporary, raw, manifest)
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    action = 're-signed' if old else 'signed'
    print(f'{path}: {manifest["NXRomName"]} {manifest["NXRomVersion"]} ({manifest["NXRomIdentifier"]}, '
          f'security version {manifest["NXRomSecurityVersion"]}) {action} with key {key_id(raw)}, '
          f'{sum(entry["type"] == "file" for entry in files.values())} files in {FILES_NAME}')
    if adhoc:
        print(f'signed ad hoc first (they had no code signature): {", ".join(adhoc)}')


def command_verify(args):
    path = Path(args.archive)
    length, signature = read_footer(path)
    if signature is None:
        fail(f'{path.name} has no release signature (RomGen.py sign)')
    digest = archive_digest(path, length)
    candidates = []
    if args.public:
        candidates.append(('given key', raw_public_key(args.public), None))
    store = None
    if args.truststore:
        store = load_truststore(args.truststore)
        candidates += [(key['name'], key['publicKey'], key.get('roms')) for key in store.get('keys', [])]
    if not candidates:
        fail('nothing to verify against: --public KEY.pub.pem and/or --truststore FILE|online')
    for name, raw, roms in candidates:
        if verify_digest(raw, digest, signature):
            manifest = read_manifest(path)
            print(f'{path}: signed by {name} (key {key_id(raw)})')
            print(f'{FILES_NAME}: {verify_file_list(path, raw, manifest)} entries, all match')
            if store is not None:
                if roms is None and name == 'given key':
                    match = next((key for key in store['keys'] if key['publicKey'] == raw), None)
                    if match is None:
                        fail(f'key {key_id(raw)} is not in TrustStore version {store["version"]}: Nyxian will not boot it')
                    roms = match.get('roms')
                if roms is not None and manifest['NXRomIdentifier'] not in roms:
                    fail(f'the key is trusted only for {", ".join(roms)}, not {manifest["NXRomIdentifier"]}')
                print(f'trusted by TrustStore version {store["version"]} for {manifest["NXRomIdentifier"]}')
            return
    fail('the signature does not match ' + ('any key of the TrustStore' if store is not None and not args.public else 'the given key'))


def command_digest(args):
    """what the TSS knows a release by: the archive digest of the signed ZIP"""
    path = Path(args.archive)
    length, signature = read_footer(path)
    if signature is None:
        fail(f'{path.name} has no release signature (RomGen.py sign)')
    print(archive_digest(path, length).hex())
    print("sign it on your key's page on developer.emexlabs.org (Signed releases) so devices can install it", file=sys.stderr)


def command_info(args):
    path = Path(args.file)
    if zipfile.is_zipfile(path):
        manifest = read_manifest(path)
        for key in ('NXRomName', 'NXRomVersion', 'NXRomIdentifier', 'NXRomSecurityVersion', 'NXRomMinimumNyxianVersion', 'NXRomExecutable'):
            print(f'{key}: {manifest.get(key)}')
        _, signature = read_footer(path)
        print('release signature: ' + ('present (verify it with RomGen.py verify)' if signature else 'none'))
        with zipfile.ZipFile(path) as archive:
            top = read_top(archive)
            print(f'signed file list ({FILES_NAME}): ' + ('present' if f'{top}/{FILES_NAME}' in archive.namelist() else 'none'))
    else:
        data = path.read_bytes()
        raw = raw_public_key(path, private=b'PRIVATE KEY' in data)
        print(f'{"private" if b"PRIVATE KEY" in data else "public"} P-256 key, key ID {key_id(raw)}')
        print(f'publicKey (hex): {raw.hex()}')


SHIMCACHE_M = r'''#include <LindChain/ProcEnvironment/Surface/cache/shimcache.h>
#include <LindChain/ProcEnvironment/Surface/libkern/patch.h>
#include <LindChain/ProcEnvironment/Surface/libkern/klog.h>

LIBKERN_DEFINE_PATCHABLE(kern_return_t, ksurface_shimcache_append_code,
                         (CCFileType fileType, const char *code))
{
    (void)fileType;
    (void)code;
    klog_log("shimcache", "guest shim source ignored by ROM host");
    return KERN_SUCCESS;
}

LIBKERN_DEFINE_PATCHABLE(kern_return_t, ksurface_shimcache_build, (void))
{
    klog_log("shimcache", "no host-side compiler; shimcache build skipped");
    return KERN_SUCCESS;
}
'''

LDE_APPLICATION_OBJECT_M = r'''#import <Frameworks/LiveProcessLegacy/LindChain/Services/bootstrapd/LDEApplicationObject.h>

@implementation LDEApplicationObject

+ (BOOL)supportsSecureCoding
{
    return YES;
}

- (instancetype)initWithNSBundle:(NSBundle *)bundle
{
    self = [super init];
    if(self && bundle)
    {
        self.bundleIdentifier = bundle.bundleIdentifier;
        self.localizedName = [bundle objectForInfoDictionaryKey:@"CFBundleDisplayName"] ?: [bundle objectForInfoDictionaryKey:@"CFBundleName"] ?: bundle.bundleIdentifier;
        self.bundlePath = bundle.bundlePath;
        self.executablePath = bundle.executablePath;
        self.iconDictionary = [bundle objectForInfoDictionaryKey:@"CFBundleIcons"];
        self.bundleVersion = [bundle objectForInfoDictionaryKey:@"CFBundleVersion"];
        self.shortVersionString = [bundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: self.bundleVersion;
        self.sdkVersion = [bundle objectForInfoDictionaryKey:@"DTPlatformVersion"];
        self.minimumSystemVersion = [bundle objectForInfoDictionaryKey:@"MinimumOSVersion"];
        self.entitlements = @{};
        self.isLaunchAllowed = YES;
        self.isFullscreenRequired = [[bundle objectForInfoDictionaryKey:@"UIRequiresFullScreen"] boolValue];

        NSDictionary<NSString*, NSNumber*> *masks = @{
            @"UIInterfaceOrientationPortrait": @(UIInterfaceOrientationMaskPortrait),
            @"UIInterfaceOrientationPortraitUpsideDown": @(UIInterfaceOrientationMaskPortraitUpsideDown),
            @"UIInterfaceOrientationLandscapeLeft": @(UIInterfaceOrientationMaskLandscapeLeft),
            @"UIInterfaceOrientationLandscapeRight": @(UIInterfaceOrientationMaskLandscapeRight),
        };
        UIInterfaceOrientationMask mask = 0;
        id orientations = [bundle objectForInfoDictionaryKey:@"UISupportedInterfaceOrientations"];
        if([orientations isKindOfClass:NSArray.class])
        {
            for(id orientation in orientations)
            {
                if([orientation isKindOfClass:NSString.class]) mask |= masks[orientation].unsignedIntegerValue;
            }
        }
        self.supportedInterfaceOrientations = mask ?: UIInterfaceOrientationMaskAllButUpsideDown;
    }
    return self;
}
- (void)encodeWithCoder:(NSCoder *)coder
{
    [coder encodeObject:self.bundleIdentifier forKey:@"bundleIdentifier"];
    [coder encodeObject:self.bundlePath forKey:@"bundlePath"];
    [coder encodeObject:self.executablePath forKey:@"executablePath"];
    [coder encodeObject:self.localizedName forKey:@"localizedName"];
    [coder encodeObject:self.containerPath forKey:@"containerPath"];
    [coder encodeObject:self.icon forKey:@"icon"];
    [coder encodeObject:self.darkIcon forKey:@"darkIcon"];
    [coder encodeObject:self.iconDictionary forKey:@"iconDictionary"];
    [coder encodeObject:self.bundleVersion forKey:@"bundleVersion"];
    [coder encodeObject:self.shortVersionString forKey:@"shortVersionString"];
    [coder encodeObject:self.sdkVersion forKey:@"sdkVersion"];
    [coder encodeObject:self.minimumSystemVersion forKey:@"minimumSystemVersion"];
    [coder encodeObject:self.entitlements forKey:@"entitlements"];
    [coder encodeObject:@(self.supportedInterfaceOrientations) forKey:@"supportedInterfaceOrientations"];
    [coder encodeObject:@(self.isLaunchAllowed) forKey:@"isLaunchAllowed"];
    [coder encodeObject:@(self.isFullscreenRequired) forKey:@"isFullscreenRequired"];
}

- (instancetype)initWithCoder:(NSCoder *)coder
{
    self = [super init];
    if(self)
    {
        _bundleIdentifier = [coder decodeObjectOfClass:NSString.class forKey:@"bundleIdentifier"];
        _bundlePath = [coder decodeObjectOfClass:NSString.class forKey:@"bundlePath"];
        _executablePath = [coder decodeObjectOfClass:NSString.class forKey:@"executablePath"];
        _localizedName = [coder decodeObjectOfClass:NSString.class forKey:@"localizedName"];
        _containerPath = [coder decodeObjectOfClass:NSString.class forKey:@"containerPath"];
        _icon = [coder decodeObjectOfClass:UIImage.class forKey:@"icon"];
        _darkIcon = [coder decodeObjectOfClass:UIImage.class forKey:@"darkIcon"];
        NSSet *plist = [NSSet setWithArray:@[NSDictionary.class, NSArray.class, NSString.class, NSNumber.class, NSData.class]];
        _iconDictionary = [coder decodeObjectOfClasses:plist forKey:@"iconDictionary"];
        _bundleVersion = [coder decodeObjectOfClass:NSString.class forKey:@"bundleVersion"];
        _shortVersionString = [coder decodeObjectOfClass:NSString.class forKey:@"shortVersionString"];
        _sdkVersion = [coder decodeObjectOfClass:NSString.class forKey:@"sdkVersion"];
        _minimumSystemVersion = [coder decodeObjectOfClass:NSString.class forKey:@"minimumSystemVersion"];
        _entitlements = [coder decodeObjectOfClasses:plist forKey:@"entitlements"];
        _supportedInterfaceOrientations = [[coder decodeObjectOfClass:NSNumber.class forKey:@"supportedInterfaceOrientations"] unsignedLongLongValue];
        _isLaunchAllowed = [[coder decodeObjectOfClass:NSNumber.class forKey:@"isLaunchAllowed"] boolValue];
        _isFullscreenRequired = [[coder decodeObjectOfClass:NSNumber.class forKey:@"isFullscreenRequired"] boolValue];
    }
    return self;
}

- (BOOL)isEqual:(id)object
{
    if(self == object)
    {
        return YES;
    }
    if(![object isKindOfClass:LDEApplicationObject.class])
    {
        return NO;
    }
    return [self.bundleIdentifier isEqualToString:((LDEApplicationObject *)object).bundleIdentifier];
}

- (NSUInteger)hash
{
    return self.bundleIdentifier.hash;
}

@end
'''

CCCOMPAT_C = r'''
#include <sys/types.h>
#include <sys/sysctl.h>
#include <stddef.h>

int CCGetMaximumPerformanceCores(void)
{
    int count = 0; size_t size = sizeof(count);
    if(sysctlbyname("hw.perflevel0.physicalcpu", &count, &size, NULL, 0) == 0 && count > 0)
    {
        return count;
    }
    count = 0; size = sizeof(count);
    if(sysctlbyname("hw.physicalcpu", &count, &size, NULL, 0) == 0 && count > 0)
    {
        return count;
    }
    return 1;
}
'''

NXBOOTSTRAP_H = r'''#ifndef NXBOOTSTRAP_H
#define NXBOOTSTRAP_H

#import <Foundation/Foundation.h>

#define NXBOOTSTRAP_NEWEST_VERSION 1

@interface NXBootstrap : NSObject

@property (nonatomic, readonly, strong, nonnull) NSURL *rootURL;
@property (nonatomic, readonly, strong, nonnull) NSURL *sdkURL;
@property (nonatomic, readonly, strong, nonnull) NSURL *includeURL;
@property (nonatomic, readonly, strong, nonnull) NSURL *projectsURL;
@property (nonatomic, readonly, strong, nonnull) NSURL *cacheURL;
@property (nonatomic, readonly, strong, nonnull) NSURL *bootstrapPlistURL;
@property (nonatomic, readonly, strong, nonnull) NSURL *swiftURL;
@property (nonatomic, readonly, strong, nonnull) NSURL *swiftModuleCacheURL;
@property (nonatomic, readonly, strong, nonnull) NSURL *rootfsURL;
@property (atomic, readonly) UInt64 version;
@property (atomic, readonly) BOOL isInstalled;

+ (instancetype _Nonnull)shared;
- (void)bootstrap;
- (NSString * _Nullable)relativeToBootstrapWithAbsolutePath:(NSString * _Nonnull)path;
- (void)clearURL:(NSURL * _Nonnull)url;
- (void)waitTillDone;
- (void)waitTillDoneNoButton;
- (BOOL)isNewest;

@end

#endif
'''

NXBOOTSTRAP_M = r'''#import <LindChain/IDEFoundation/NXBootstrap.h>

@implementation NXBootstrap {
    dispatch_group_t _bootstrapGroup;
    dispatch_once_t _bootstrapOnce;
    BOOL _bootstrapSucceeded;
}

+ (instancetype)shared
{
    static NXBootstrap *shared;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[NXBootstrap alloc] init];
    });
    return shared;
}

- (instancetype)init
{
    self = [super init];
    if(self)
    {
        _bootstrapGroup = dispatch_group_create();
        dispatch_group_enter(_bootstrapGroup);
    }
    return self;
}

- (NSURL *)rootURL
{
    static NSURL *url;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSString *home = NSHomeDirectory();
        if(![home hasPrefix:@"/private/"])
        {
            home = [@"/private" stringByAppendingPathComponent:home];
        }
        url = [NSURL fileURLWithPath:[home stringByAppendingPathComponent:@"Documents"] isDirectory:YES];
    });
    return url;
}

- (NSURL *)rootfsURL { return [self.rootURL URLByAppendingPathComponent:@"rootfs" isDirectory:YES]; }
- (NSURL *)sdkURL { return [self.rootURL URLByAppendingPathComponent:@"SDK" isDirectory:YES]; }
- (NSURL *)includeURL { return [self.rootURL URLByAppendingPathComponent:@"Include" isDirectory:YES]; }
- (NSURL *)projectsURL { return [self.rootURL URLByAppendingPathComponent:@"Projects" isDirectory:YES]; }
- (NSURL *)cacheURL { return [self.rootURL URLByAppendingPathComponent:@"Cache" isDirectory:YES]; }
- (NSURL *)bootstrapPlistURL { return [self.rootURL URLByAppendingPathComponent:@"bootstrap.plist"]; }
- (NSURL *)swiftURL { return [self.rootURL URLByAppendingPathComponent:@"swift" isDirectory:YES]; }
- (NSURL *)swiftModuleCacheURL { return [self.rootURL URLByAppendingPathComponent:@"ModuleCache" isDirectory:YES]; }

- (UInt64)version
{
    NSDictionary *plist = [NSDictionary dictionaryWithContentsOfURL:self.bootstrapPlistURL];
    NSNumber *n = plist[@"BootstrapVersion"];
    return [n isKindOfClass:NSNumber.class] ? n.unsignedLongLongValue : 0;
}

- (BOOL)isInstalled { return self.version > 0; }
- (BOOL)isNewest { return self.version >= NXBOOTSTRAP_NEWEST_VERSION; }

- (void)bootstrap
{
    dispatch_once(&_bootstrapOnce, ^{
        NSFileManager *fm = NSFileManager.defaultManager;
        NSError *error = nil;
        NSArray<NSURL *> *directories = @[
            self.rootURL,
            self.rootfsURL,
            [self.rootfsURL URLByAppendingPathComponent:@"tmp" isDirectory:YES],
            [self.rootURL URLByAppendingPathComponent:@"mntfs/bootfs" isDirectory:YES],
            [self.rootURL URLByAppendingPathComponent:@"mntfs/lsfs" isDirectory:YES],
            [self.rootURL URLByAppendingPathComponent:@"RootCAs" isDirectory:YES],
        ];

        BOOL ok = YES;
        for (NSURL *url in directories) {
            if (![fm createDirectoryAtURL:url
              withIntermediateDirectories:YES
                               attributes:nil
                                    error:&error]) {
                NSLog(@"NXBootstrap: failed to create %@: %@", url.path, error);
                ok = NO;
                break;
            }
        }

        if(ok)
        {
            NSDictionary *plist = @{ @"BootstrapVersion": @(NXBOOTSTRAP_NEWEST_VERSION) };
            ok = [plist writeToURL:self.bootstrapPlistURL atomically:YES];
        }
        _bootstrapSucceeded = ok;
        dispatch_group_leave(_bootstrapGroup);
    });
}

- (void)waitTillDone
{
    dispatch_group_wait(_bootstrapGroup, DISPATCH_TIME_FOREVER);
}

- (void)waitTillDoneNoButton
{
    [self waitTillDone];
}

- (void)clearURL:(NSURL *)url
{
    if(url)
    {
        [NSFileManager.defaultManager removeItemAtURL:url error:nil];
    }
}

- (NSString *)relativeToBootstrapWithAbsolutePath:(NSString *)path
{
    if(!path)
    {
        return nil;
    }
    NSString *root = self.rootURL.path.stringByStandardizingPath;
    NSString *candidate = path.stringByStandardizingPath;
    if([candidate isEqualToString:root])
    {
        return @"";
    }
    NSString *prefix = [root stringByAppendingString:@"/"];
    return [candidate hasPrefix:prefix] ? [candidate substringFromIndex:prefix.length] : nil;
}

@end
'''

HELLO_MAIN_M = r'''#import <UIKit/UIKit.h>

@interface HelloViewController : UIViewController

@property (nonatomic, strong) UILabel *statusLabel;

@end

@implementation HelloViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.systemBackgroundColor;

    UIImageView *icon = [[UIImageView alloc] initWithImage:[UIImage systemImageNamed:@"sparkles"]];
    icon.translatesAutoresizingMaskIntoConstraints = NO;
    icon.contentMode = UIViewContentModeScaleAspectFit;
    icon.tintColor = UIColor.systemIndigoColor;
    [icon.widthAnchor constraintEqualToConstant:72.0].active = YES;
    [icon.heightAnchor constraintEqualToConstant:72.0].active = YES;

    UILabel *title = [UILabel new];
    title.text = @"Hello!";
    title.font = [UIFont systemFontOfSize:34.0 weight:UIFontWeightBold];
    title.textAlignment = NSTextAlignmentCenter;

    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[icon, title]];
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    stack.axis = UILayoutConstraintAxisVertical;
    stack.alignment = UIStackViewAlignmentCenter;
    stack.spacing = 18.0;
    [self.view addSubview:stack];

    [NSLayoutConstraint activateConstraints:@[
        [stack.leadingAnchor constraintGreaterThanOrEqualToAnchor:self.view.safeAreaLayoutGuide.leadingAnchor constant:24.0],
        [stack.trailingAnchor constraintLessThanOrEqualToAnchor:self.view.safeAreaLayoutGuide.trailingAnchor constant:-24.0],
        [stack.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [stack.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor],
    ]];
}

@end

@interface HelloSceneDelegate : UIResponder <UIWindowSceneDelegate>

@property (nonatomic, strong) UIWindow *window;

@end

@implementation HelloSceneDelegate

- (void)scene:(UIScene *)scene willConnectToSession:(UISceneSession *)session options:(UISceneConnectionOptions *)connectionOptions
{
    if(![scene isKindOfClass:UIWindowScene.class])
    {
        return;
    }

    UIWindow *window = [[UIWindow alloc] initWithWindowScene:(UIWindowScene *)scene];
    window.rootViewController = [HelloViewController new];
    self.window = window;
    [window makeKeyAndVisible];
}

@end

@interface HelloAppDelegate : UIResponder <UIApplicationDelegate>
@end

@implementation HelloAppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    return YES;
}

- (UISceneConfiguration *)application:(UIApplication *)application configurationForConnectingSceneSession:(UISceneSession *)connectingSceneSession options:(UISceneConnectionOptions *)options
{
    UISceneConfiguration *configuration = [[UISceneConfiguration alloc] initWithName:@"Default Configuration" sessionRole:connectingSceneSession.role];
    configuration.delegateClass = HelloSceneDelegate.class;
    return configuration;
}

@end

__attribute__((visibility("default")))
int main(int argc, char *argv[])
{
    @autoreleasepool
    {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass(HelloAppDelegate.class));
    }
}
'''

HELLO_INFO_PLIST = r'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key><string>en</string>
    <key>CFBundleDisplayName</key><string>Hello</string>
    <key>CFBundleExecutable</key><string>Hello</string>
    <key>CFBundleIdentifier</key><string>org.emexlabs.rom.hello</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>CFBundleName</key><string>Hello</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>1.0</string>
    <key>CFBundleVersion</key><string>1</string>
    <key>LSRequiresIPhoneOS</key><true/>
    <key>MinimumOSVersion</key><string>18.0</string>
    <key>UIRequiresFullScreen</key><false/>
    <key>UISupportedInterfaceOrientations</key>
    <array>
        <string>UIInterfaceOrientationPortrait</string>
        <string>UIInterfaceOrientationLandscapeLeft</string>
        <string>UIInterfaceOrientationLandscapeRight</string>
    </array>
    <key>UIApplicationSceneManifest</key>
    <dict>
        <key>UIApplicationSupportsMultipleScenes</key><false/>
        <key>UISceneConfigurations</key>
        <dict>
            <key>UIWindowSceneSessionRoleApplication</key>
            <array>
                <dict>
                    <key>UISceneConfigurationName</key><string>Default Configuration</string>
                    <key>UISceneDelegateClassName</key><string>HelloSceneDelegate</string>
                </dict>
            </array>
        </dict>
    </dict>
</dict>
</plist>
'''

NXMAINSLOT_M = r'''#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <errno.h>
#import <string.h>
#include <limits.h>
#include <stdlib.h>
#import <LindChain/IDEFoundation/NXBootstrap.h>
#import <LindChain/ProcEnvironment/PEUserspaceManager.h>
#import <LindChain/ProcEnvironment/PEProcessManager.h>
#import <LindChain/ProcEnvironment/PEFileTable.h>
#import <Frameworks/LiveProcessLegacy/LindChain/Services/bootstrapd/LDEApplicationObject.h>
#import <LindChain/ProcEnvironment/Surface/trust/trust.h>
#import <LindChain/ProcEnvironment/Surface/libkern/klog.h>
#import <LindChain/ProcEnvironment/Surface/proc/list.h>
#import <LindChain/ProcEnvironment/Surface/proc/lookup.h>
#import <LindChain/ProcEnvironment/Surface/proc/spawn.h>
#import <LindChain/ProcEnvironment/Surface/lock.h>
#import <LindChain/ProcEnvironment/Surface/libkern/radix/radix.h>
#import <LindChain/WindowServer/NXWindowServer.h>
#import <LindChain/WindowServer/Session/NXWindowSessionApplication.h>

static BOOL NXROMDefaultBool(NSString *key, BOOL fallback)
{
    id value = [NSUserDefaults.standardUserDefaults objectForKey:key];
    return value ? [value boolValue] : fallback;
}

extern NSString *NXROMApplicationSourcePath(void);

#pragma mark - The ROM and its applications

static NSString *NXROMSlotDirectory(void)
{
    NSString *applications = NXROMApplicationSourcePath();
    return applications.length > 0 ? applications.stringByDeletingLastPathComponent : nil;
}

static NSString *NXROMDisplayName(void)
{
    NSString *slot = NXROMSlotDirectory();
    NSDictionary *manifest = slot ? [NSDictionary dictionaryWithContentsOfFile:[slot stringByAppendingPathComponent:@"manifest.plist"]] : nil;
    NSString *name = manifest[@"NXRomName"];
    return ([name isKindOfClass:NSString.class] && name.length > 0) ? name : @"ROM";
}

@interface NXROMApplication : NSObject
@property (nonatomic, strong) NSBundle *bundle;
@property (nonatomic, copy) NSString *bundleIdentifier;
@property (nonatomic, copy) NSString *name;
@property (nonatomic, strong) UIImage *icon;
@end

@implementation NXROMApplication
@end

static UIImage *NXROMApplicationIcon(NSBundle *bundle)
{
    NSDictionary *icons = [bundle objectForInfoDictionaryKey:@"CFBundleIcons"];
    NSDictionary *primary = [icons isKindOfClass:NSDictionary.class] ? icons[@"CFBundlePrimaryIcon"] : nil;
    NSArray *files = [primary isKindOfClass:NSDictionary.class] ? primary[@"CFBundleIconFiles"] : nil;
    if(![files isKindOfClass:NSArray.class])
    {
        return nil;
    }
    for(NSString *file in files.reverseObjectEnumerator)
    {
        if(![file isKindOfClass:NSString.class])
        {
            continue;
        }
        UIImage *image = [UIImage imageNamed:file inBundle:bundle compatibleWithTraitCollection:nil];
        if(image != nil)
        {
            return image;
        }
    }
    return nil;
}

static NSArray<NXROMApplication *> *NXROMApplications(void)
{
    NSString *applications = NXROMApplicationSourcePath();
    NSMutableArray<NXROMApplication *> *result = [NSMutableArray array];
    if(applications.length == 0)
    {
        return result;
    }
    for(NSString *entry in [NSFileManager.defaultManager contentsOfDirectoryAtPath:applications error:nil])
    {
        if(![entry.pathExtension isEqualToString:@"app"])
        {
            continue;
        }
        NSBundle *bundle = [NSBundle bundleWithPath:[applications stringByAppendingPathComponent:entry]];
        if(bundle.bundleIdentifier.length == 0 || bundle.executablePath == nil)
        {
            continue;
        }
        NXROMApplication *application = [NXROMApplication new];
        application.bundle = bundle;
        application.bundleIdentifier = bundle.bundleIdentifier;
        application.name = [bundle objectForInfoDictionaryKey:@"CFBundleDisplayName"] ?: [bundle objectForInfoDictionaryKey:@"CFBundleName"] ?: entry.stringByDeletingPathExtension;
        application.icon = NXROMApplicationIcon(bundle);
        [result addObject:application];
    }
    [result sortUsingComparator:^NSComparisonResult(NXROMApplication *a, NXROMApplication *b) {
        return [a.name localizedCaseInsensitiveCompare:b.name];
    }];
    return result;
}

#pragma mark - Launching

static dispatch_queue_t NXROMLaunchQueue(void)
{
    static dispatch_queue_t queue;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        queue = dispatch_queue_create("org.emexlabs.rom.launch", DISPATCH_QUEUE_SERIAL);
    });
    return queue;
}

static NSMutableDictionary<NSString *, NSDate *> *NXROMLaunchTimes(void)
{
    static NSMutableDictionary *times;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ times = [NSMutableDictionary dictionary]; });
    return times;
}

static BOOL NXROMActivateWindow(NSString *bundleIdentifier)
{
    NXWindowServer *windowServer = [NXWindowServer shared];
    NXWindowSession *session = [windowServer windowSessionForBundleIdentifier:bundleIdentifier];
    if(session == nil || session.window == nil)
    {
        return NO;
    }
    if(UIDevice.currentDevice.userInterfaceIdiom == UIUserInterfaceIdiomPhone)
    {
        [windowServer activateWindowForIdentifier:session.windowIdentifier animated:YES withCompletion:nil];
    }
    else
    {
        [session.window focusWindow];
    }
    return YES;
}

static void NXROMSpawnApplication(NXROMApplication *application)
{
    NSString *executablePath = application.bundle.executablePath;

    PEFileTable *table = [PEFileTable emptyTable];
    [table appendFileDescriptor:STDOUT_FILENO withMappingToLoc:STDOUT_FILENO];
    [table appendFileDescriptor:STDERR_FILENO withMappingToLoc:STDERR_FILENO];

    errno = 0;
    pid_t pid = [[PEProcessManager shared] spawnProcessWithItems:@{
        @"PEExecutablePath": executablePath,
        @"PEArguments": @[ executablePath ],
        @"PEWorkingDirectory": NXBootstrap.shared.rootfsURL.path,
        @"PEEnvironment": @{},
        @"PEFileTable": table,
    } withKernelSurfaceProcess:NULL];
    if(pid < 0)
    {
        int error = errno;
        klog_log("NXMainSlot", "spawning %s failed: %s", executablePath.UTF8String, error ? strerror(error) : "rejected");
        [NXROMLaunchTimes() removeObjectForKey:application.bundleIdentifier];
        return;
    }

    PEProcess *process = [[PEProcessManager shared] processForProcessIdentifier:pid];
    if(process != nil && process.bundleIdentifier == nil)
    {
        process.applicationObject = [[LDEApplicationObject alloc] initWithNSBundle:application.bundle];
        process.bundleIdentifier = application.bundleIdentifier;
        process.displayName = application.name;
    }
    klog_log("NXMainSlot", "launched %s as pid %d", application.bundleIdentifier.UTF8String, pid);
}

static void NXROMOpenApplication(NXROMApplication *application)
{
    if(NXROMActivateWindow(application.bundleIdentifier))
    {
        return;
    }
    dispatch_async(NXROMLaunchQueue(), ^{
        NSString *bundleIdentifier = application.bundleIdentifier;
        PEProcess *running = [[PEProcessManager shared] processForBundleIdentifier:bundleIdentifier];
        if(running != nil)
        {
            NSDate *launched = NXROMLaunchTimes()[bundleIdentifier];
            if(launched != nil && -launched.timeIntervalSinceNow < 5.0)
            {
                return;
            }
            [running forceTerminate];
        }
        NXROMLaunchTimes()[bundleIdentifier] = [NSDate date];
        NXROMSpawnApplication(application);
    });
}

#pragma mark - Process viewer

@interface NXROMProcessEntry : NSObject
@property (nonatomic) BOOL isKernel;
@property (nonatomic) pid_t pid;
@property (nonatomic) pid_t ppid;
@property (nonatomic) uid_t uid;
@property (nonatomic, copy) NSString *name;
@end

@implementation NXROMProcessEntry

- (BOOL)isEqual:(id)object
{
    if(![object isKindOfClass:NXROMProcessEntry.class])
    {
        return NO;
    }
    NXROMProcessEntry *other = object;
    return other.pid == self.pid && other.ppid == self.ppid && other.uid == self.uid &&
           other.isKernel == self.isKernel && [other.name isEqualToString:self.name];
}

- (NSUInteger)hash
{
    return (NSUInteger)self.pid;
}

@end

typedef struct {
    kinfo_proc_t *kp;
    size_t count;
    size_t capacity;
} NXROMProcessWalk;

static void NXROMProcessWalkCallback(uint64_t ident, void *value, void *ctx)
{
    NXROMProcessWalk *walk = ctx;
    ksurface_proc_t *proc = value;
    if(walk->count >= walk->capacity || !kvo_retain(proc))
    {
        return;
    }
    kvo_rdlock(proc);
    if(proc->bsd.kp_proc.p_stat != SZOMB)
    {
        memcpy(&walk->kp[walk->count++], &proc->bsd, sizeof(kinfo_proc_t));
    }
    kvo_unlock(proc);
    kvo_release(proc);
}

static NSArray<NXROMProcessEntry *> *NXROMProcessList(void)
{
    NSMutableArray<NXROMProcessEntry *> *entries = [NSMutableArray array];
    NXROMProcessWalk walk = {0};

    proc_table_rdlock();
    walk.capacity = ksurface->proc_info.proc_count;
    walk.kp = walk.capacity > 0 ? calloc(walk.capacity, sizeof(kinfo_proc_t)) : NULL;
    if(walk.kp != NULL)
    {
        radix_walk(&(ksurface->proc_info.tree), NXROMProcessWalkCallback, &walk);
    }
    proc_table_unlock();

    for(size_t i = 0; i < walk.count; i++)
    {
        NXROMProcessEntry *entry = [NXROMProcessEntry new];
        entry.pid = walk.kp[i].kp_proc.p_pid;
        entry.isKernel = (entry.pid == proc_getpid(kernel_proc_));
        entry.ppid = walk.kp[i].kp_eproc.e_ppid;
        entry.uid = walk.kp[i].kp_eproc.e_ucred.cr_uid;

        char comm[MAXCOMLEN + 1] = {0};
        memcpy(comm, walk.kp[i].kp_proc.p_comm, MAXCOMLEN);
        NSString *name = [NSString stringWithUTF8String:comm];
        PEProcess *process = [[PEProcessManager shared] processForProcessIdentifier:entry.pid];
        if(process.displayName.length > 0)
        {
            name = process.displayName;
        }
        entry.name = name.length > 0 ? name : @"?";
        [entries addObject:entry];
    }
    free(walk.kp);

    [entries sortUsingComparator:^NSComparisonResult(NXROMProcessEntry *a, NXROMProcessEntry *b) {
        return a.pid < b.pid ? NSOrderedAscending : (a.pid > b.pid ? NSOrderedDescending : NSOrderedSame);
    }];
    return entries;
}

static NSString *NXROMSignalName(int sig)
{
    if(sig > 0 && sig < NSIG)
    {
        return [@"SIG" stringByAppendingString:@(sys_signame[sig]).uppercaseString];
    }
    return [NSString stringWithFormat:@"signal %d", sig];
}

static NSString *NXROMSignalProcess(pid_t pid, int sig)
{
    ksurface_proc_t *proc = NULL;
    if(proc_for_pid(pid, &proc) != KERN_SUCCESS || proc == NULL)
    {
        return @"the process no longer exists";
    }
    kern_return_t kr = proc_kill(proc, sig);
    kvo_release(proc);
    if(kr != KERN_SUCCESS)
    {
        return [NSString stringWithFormat:@"the kernel surface did not deliver it (%s)", mach_error_string(kr)];
    }
    klog_log("NXMainSlot", "sent %s to pid %d", NXROMSignalName(sig).UTF8String, pid);
    return nil;
}

@interface NXROMProcessesViewController : UITableViewController
@property (nonatomic, copy) NSArray<NXROMProcessEntry *> *processes;
@property (nonatomic, strong) NSTimer *refreshTimer;
@property (nonatomic) BOOL refreshing;
@property (nonatomic) NSInteger openMenus;
@end

@implementation NXROMProcessesViewController

- (instancetype)init
{
    return [super initWithStyle:UITableViewStyleInsetGrouped];
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.title = @"Processes";
    self.navigationItem.largeTitleDisplayMode = UINavigationItemLargeTitleDisplayModeNever;
    [self.tableView registerClass:UITableViewCell.class forCellReuseIdentifier:@"process"];
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    [self refresh];
    __weak typeof(self) weakSelf = self;
    self.refreshTimer = [NSTimer scheduledTimerWithTimeInterval:1.0 repeats:YES block:^(NSTimer *timer) {
        [weakSelf refresh];
    }];
}

- (void)viewWillDisappear:(BOOL)animated
{
    [super viewWillDisappear:animated];
    [self.refreshTimer invalidate];
    self.refreshTimer = nil;
}

- (void)refresh
{
    if(self.refreshing || self.openMenus > 0 || self.tableView.isEditing || self.tableView.isTracking || self.tableView.isDecelerating)
    {
        return;
    }
    self.refreshing = YES;
    __weak typeof(self) weakSelf = self;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSArray<NXROMProcessEntry *> *processes = NXROMProcessList();
        dispatch_async(dispatch_get_main_queue(), ^{
            NXROMProcessesViewController *controller = weakSelf;
            if(controller == nil)
            {
                return;
            }
            controller.refreshing = NO;
            if([processes isEqualToArray:controller.processes ?: @[]] && controller.processes != nil)
            {
                return;
            }
            UITableView *table = controller.tableView;
            if(controller.processes != nil &&
               (controller.openMenus > 0 || table.isEditing || table.isTracking || table.isDragging || table.isDecelerating || controller.presentedViewController != nil))
            {
                return;
            }
            controller.processes = processes;
            [table reloadData];
        });
    });
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section
{
    return self.processes.count;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section
{
    return [NSString stringWithFormat:@"%lu processes", (unsigned long)self.processes.count];
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"process" forIndexPath:indexPath];
    NXROMProcessEntry *entry = self.processes[indexPath.row];
    UIListContentConfiguration *content = [UIListContentConfiguration subtitleCellConfiguration];
    content.text = entry.name;
    content.secondaryText = entry.isKernel ? [NSString stringWithFormat:@"pid %d · kernel", entry.pid]
                                           : [NSString stringWithFormat:@"pid %d · ppid %d · uid %u", entry.pid, entry.ppid, entry.uid];
    content.secondaryTextProperties.color = UIColor.secondaryLabelColor;
    content.image = [UIImage systemImageNamed:entry.isKernel ? @"cpu" : @"gearshape.2"];
    content.imageProperties.tintColor = UIColor.secondaryLabelColor;
    cell.contentConfiguration = content;
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    return cell;
}

- (void)sendSignal:(int)sig toEntry:(NXROMProcessEntry *)entry
{
    pid_t pid = entry.pid;
    NSString *name = entry.name;
    __weak typeof(self) weakSelf = self;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *failure = NXROMSignalProcess(pid, sig);
        dispatch_async(dispatch_get_main_queue(), ^{
            NXROMProcessesViewController *controller = weakSelf;
            if(controller == nil)
            {
                return;
            }
            [controller refresh];
            if(failure != nil)
            {
                UIAlertController *alert = [UIAlertController alertControllerWithTitle:[NSString stringWithFormat:@"%@ not sent", NXROMSignalName(sig)]
                                                                               message:[NSString stringWithFormat:@"%@ (pid %d): %@.", name, pid, failure]
                                                                        preferredStyle:UIAlertControllerStyleAlert];
                [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
                [controller presentViewController:alert animated:YES completion:nil];
            }
        });
    });
}

- (NSIndexPath *)tableView:(UITableView *)tableView willSelectRowAtIndexPath:(NSIndexPath *)indexPath
{
    return nil;
}

- (UIMenu *)signalMenuForEntry:(NXROMProcessEntry *)entry
{
    struct { const char *title; const char *image; int sig; BOOL destructive; } signals[] = {
        { "Terminate", "xmark.circle", SIGTERM, YES },
        { "Kill", "bolt.circle", SIGKILL, YES },
        { "Interrupt", "hand.raised", SIGINT, NO },
        { "Hang Up", "phone.down", SIGHUP, NO },
        { "Stop", "pause.circle", SIGSTOP, NO },
        { "Continue", "play.circle", SIGCONT, NO },
        { "User Signal 1", "1.circle", SIGUSR1, NO },
        { "User Signal 2", "2.circle", SIGUSR2, NO },
    };
    NSMutableArray<UIMenuElement *> *control = [NSMutableArray array];
    NSMutableArray<UIMenuElement *> *ending = [NSMutableArray array];
    __weak typeof(self) weakSelf = self;
    for(size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); i++)
    {
        int sig = signals[i].sig;
        UIAction *action = [UIAction actionWithTitle:@(signals[i].title)
                                               image:[UIImage systemImageNamed:@(signals[i].image)]
                                          identifier:nil
                                             handler:^(UIAction *a) {
            [weakSelf sendSignal:sig toEntry:entry];
        }];
        action.subtitle = NXROMSignalName(sig);
        if(signals[i].destructive)
        {
            action.attributes = UIMenuElementAttributesDestructive;
            [ending addObject:action];
        }
        else
        {
            [control addObject:action];
        }
    }
    return [UIMenu menuWithTitle:[NSString stringWithFormat:@"%@ · pid %d", entry.name, entry.pid] children:@[
        [UIMenu menuWithTitle:@"" image:nil identifier:nil options:UIMenuOptionsDisplayInline children:control],
        [UIMenu menuWithTitle:@"" image:nil identifier:nil options:UIMenuOptionsDisplayInline children:ending],
    ]];
}

- (UIContextMenuConfiguration *)tableView:(UITableView *)tableView contextMenuConfigurationForRowAtIndexPath:(NSIndexPath *)indexPath point:(CGPoint)point
{
    NXROMProcessEntry *entry = self.processes[indexPath.row];
    if(entry.isKernel)
    {
        return nil;
    }
    __weak typeof(self) weakSelf = self;
    return [UIContextMenuConfiguration configurationWithIdentifier:nil previewProvider:nil actionProvider:^UIMenu *(NSArray<UIMenuElement *> *suggested) {
        return [weakSelf signalMenuForEntry:entry];
    }];
}

- (void)tableView:(UITableView *)tableView willDisplayContextMenuWithConfiguration:(UIContextMenuConfiguration *)configuration animator:(id<UIContextMenuInteractionAnimating>)animator
{
    self.openMenus++;
}

- (void)tableView:(UITableView *)tableView willEndContextMenuInteractionWithConfiguration:(UIContextMenuConfiguration *)configuration animator:(id<UIContextMenuInteractionAnimating>)animator
{
    if(self.openMenus > 0) self.openMenus--;
}

@end

#pragma mark - Home

@interface NXROMApplicationsViewController : UITableViewController
@property (nonatomic, copy) NSArray<NXROMApplication *> *applications;
@property (nonatomic, copy) NSArray<NSNumber *> *runningPids;
@property (nonatomic, strong) NSTimer *refreshTimer;
@end

@implementation NXROMApplicationsViewController

- (instancetype)init
{
    return [super initWithStyle:UITableViewStyleInsetGrouped];
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.title = NXROMDisplayName();
    self.navigationItem.largeTitleDisplayMode = UINavigationItemLargeTitleDisplayModeAlways;
    [self.tableView registerClass:UITableViewCell.class forCellReuseIdentifier:@"application"];

    self.navigationItem.leftBarButtonItem = [[UIBarButtonItem alloc] initWithImage:[UIImage systemImageNamed:@"list.bullet.rectangle"]
                                                                             style:UIBarButtonItemStylePlain
                                                                            target:self
                                                                            action:@selector(showProcesses:)];
    self.navigationItem.leftBarButtonItem.accessibilityLabel = @"Processes";

    UIBarButtonItem *switcher = [[UIBarButtonItem alloc] initWithImage:[UIImage systemImageNamed:@"square.stack.3d.up"]
                                                                 style:UIBarButtonItemStylePlain
                                                                target:self
                                                                action:@selector(showAppSwitcher:)];
    switcher.accessibilityLabel = @"App Switcher";
    switcher.enabled = (UIDevice.currentDevice.userInterfaceIdiom == UIUserInterfaceIdiomPhone);
    self.navigationItem.rightBarButtonItem = switcher;
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    self.applications = NXROMApplications();
    self.runningPids = [self currentRunningPids];
    [self.tableView reloadData];
    __weak typeof(self) weakSelf = self;
    self.refreshTimer = [NSTimer scheduledTimerWithTimeInterval:1.0 repeats:YES block:^(NSTimer *timer) {
        [weakSelf refreshRunningState];
    }];
}

- (void)viewWillDisappear:(BOOL)animated
{
    [super viewWillDisappear:animated];
    [self.refreshTimer invalidate];
    self.refreshTimer = nil;
}

- (NSArray<NSNumber *> *)currentRunningPids
{
    NSMutableArray<NSNumber *> *pids = [NSMutableArray arrayWithCapacity:self.applications.count];
    for(NXROMApplication *application in self.applications)
    {
        PEProcess *process = [[PEProcessManager shared] processForBundleIdentifier:application.bundleIdentifier];
        [pids addObject:@(process ? process.pid : 0)];
    }
    return pids;
}

- (void)refreshRunningState
{
    NSArray<NSNumber *> *pids = [self currentRunningPids];
    if([pids isEqualToArray:self.runningPids])
    {
        return;
    }
    NSMutableArray<NSIndexPath *> *changed = [NSMutableArray array];
    for(NSUInteger row = 0; row < pids.count && row < self.runningPids.count; row++)
    {
        if(![pids[row] isEqualToNumber:self.runningPids[row]])
        {
            [changed addObject:[NSIndexPath indexPathForRow:(NSInteger)row inSection:0]];
        }
    }
    self.runningPids = pids;
    [self.tableView reconfigureRowsAtIndexPaths:changed];
}

- (void)showProcesses:(id)sender
{
    UINavigationController *sheet = [[UINavigationController alloc] initWithRootViewController:[NXROMProcessesViewController new]];
    sheet.modalPresentationStyle = UIModalPresentationPageSheet;
    UISheetPresentationController *presentation = sheet.sheetPresentationController;
    presentation.detents = @[ UISheetPresentationControllerDetent.mediumDetent, UISheetPresentationControllerDetent.largeDetent ];
    presentation.prefersGrabberVisible = YES;
    presentation.prefersScrollingExpandsWhenScrolledToEdge = NO;
    presentation.prefersEdgeAttachedInCompactHeight = YES;
    [self presentViewController:sheet animated:YES completion:nil];
}

- (void)showAppSwitcher:(id)sender
{
    [[NXWindowServer shared] showAppSwitcherExternal];
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section
{
    return self.applications.count;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section
{
    return @"Applications";
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section
{
    return self.applications.count == 0 ? @"This ROM ships no apps (Application/*.app)." : nil;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"application" forIndexPath:indexPath];
    NXROMApplication *application = self.applications[indexPath.row];
    PEProcess *process = [[PEProcessManager shared] processForBundleIdentifier:application.bundleIdentifier];

    UIListContentConfiguration *content = [UIListContentConfiguration subtitleCellConfiguration];
    content.text = application.name;
    content.secondaryText = process ? [NSString stringWithFormat:@"%@ · running, pid %d", application.bundleIdentifier, process.pid]
                                    : application.bundleIdentifier;
    content.secondaryTextProperties.color = UIColor.secondaryLabelColor;
    content.image = application.icon ?: [UIImage systemImageNamed:@"app.dashed"];
    content.imageProperties.maximumSize = CGSizeMake(40.0, 40.0);
    content.imageProperties.reservedLayoutSize = CGSizeMake(40.0, 40.0);
    content.imageProperties.cornerRadius = application.icon ? 9.0 : 0.0;
    cell.contentConfiguration = content;
    cell.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    NXROMOpenApplication(self.applications[indexPath.row]);
}

@end

UIViewController *NXMainSlot(void)
{
    NSString *mode = [NSUserDefaults.standardUserDefaults stringForKey:@"nyxian.boot.entitlements.mode"];
    PEEnforcementMode enforcement = kPEEnforcementModeEnforcing;
    if([mode isEqualToString:@"permissive"])
    {
        enforcement = kPEEnforcementModePermissive;
    }
    else if ([mode isEqualToString:@"disabled"])
    {
        enforcement = kPEEnforcementModeDisabled;
    }

    trust_enforcement_set_mode(enforcement);
    klog_set_obfuscation(NXROMDefaultBool(@"nyxian.boot.log.obfuscated", YES));

    [[NXBootstrap shared] bootstrap];
    [[NXBootstrap shared] waitTillDoneNoButton];

    BOOL loadKexts = NXROMDefaultBool(@"nyxian.boot.kextLoading", YES);
    [[PEUserspaceManager shared] bootWithKextLoadingEnabled:loadKexts];

    UINavigationController *navigation = [[UINavigationController alloc] initWithRootViewController:[NXROMApplicationsViewController new]];
    navigation.navigationBar.prefersLargeTitles = YES;
    return navigation;
}

__attribute__((visibility("default")))
void *NXSlotMain(void)
{
    UIViewController *root = NXMainSlot();
    return (__bridge_retained void *)root;
}

__attribute__((visibility("default")))
void *NXSlotCreateWindow(void *scenePtr)
{
    if(scenePtr == NULL)
    {
        return NULL;
    }
    UIWindowScene *scene = (__bridge UIWindowScene *)scenePtr;
    NXWindowServer *window = [NXWindowServer sharedWithWindowScene:scene];
    return window ? (__bridge_retained void *)window : NULL;
}

__attribute__((visibility("default")))
void NXSlotDidAppear(void)
{
    [[NXWindowServer shared] makeKeyAndVisible];
}
'''

def nxmainslot_with_boot_args(source):
    def swap(text, old, new):
        if text.count(old) != 1:
            fail(f'NXMainSlot template changed, cannot add boot arguments at: {old.strip()[:60]}')
        return text.replace(old, new)
    source = swap(source, '#import <LindChain/WindowServer/Session/NXWindowSessionApplication.h>\n',
                  '#import <LindChain/WindowServer/Session/NXWindowSessionApplication.h>\n#include <NXBootArgs.h>\n')
    source = swap(source, """static BOOL NXROMDefaultBool(NSString *key, BOOL fallback)
{
    id value = [NSUserDefaults.standardUserDefaults objectForKey:key];
    return value ? [value boolValue] : fallback;
}

""", '')
    source = swap(source, '    klog_set_obfuscation(NXROMDefaultBool(@"nyxian.boot.log.obfuscated", YES));\n',
                  '    char bootArguments[NX_BOOT_ARGS_MAX];\n'
                  '    NXBootArgsCopy(bootArguments, sizeof(bootArguments));\n'
                  '    klog_set_obfuscation(NXBootArgsGetBool(bootArguments, NX_BOOT_ARG_KLOG_OBFUSCATE, true));\n')
    source = swap(source, '    BOOL loadKexts = NXROMDefaultBool(@"nyxian.boot.kextLoading", YES);\n',
                  '    BOOL loadKexts = !NXBootArgsHasFlag(bootArguments, NX_BOOT_ARG_NO_KEXTS);\n')
    return source

class _PatchArgs:
    def __init__(self, path):
        self.argv = ['patch', str(path)]


def _run_patch(code, path):
    exec(compile(code, '<patch>', 'exec'), {'__name__': '__patch__', 'sys': _PatchArgs(path)})


_PATCH_MDK_IMPORT = r"""from pathlib import Path
p = Path(sys.argv[1])
s = p.read_text()
s = s.replace('#import <MobileDevelopmentKit/MDKThreadPool.h>\n', '')
p.write_text(s)
"""


def patch_mdk_import(path):
    _run_patch(_PATCH_MDK_IMPORT, path)


_PATCH_SWIFT_IMPORT = r"""from pathlib import Path
p = Path(sys.argv[1])
s = p.read_text()
s = s.replace('#import <Nyxian-Swift.h>\n', '')
p.write_text(s)
"""


def patch_swift_import(path):
    _run_patch(_PATCH_SWIFT_IMPORT, path)


_PATCH_PEUM_IMPORTS = r"""from pathlib import Path
p = Path(sys.argv[1])
s = p.read_text()
anchor = '#import <LindChain/IDEFoundation/NXBootstrap.h>\n'
extra = (
    '#import <LindChain/IDEFoundation/NXAlertDiagnosticPresenter.h>\n'
    '#import <LindChain/ProcEnvironment/Utils/misc.h>\n'
)
if extra not in s:
    s = s.replace(anchor, anchor + extra)
p.write_text(s)
"""


def patch_peum_imports(path):
    _run_patch(_PATCH_PEUM_IMPORTS, path)


_PATCH_NXPLIST = r"""from pathlib import Path
import re
p = Path(sys.argv[1])
s = p.read_text()
s = s.replace('#import <CommonCrypto/CommonDigest.h>\n', '')
s = s.replace('#import <LindChain/Utils/Swizzle.h>\n', '')
replacement = '''- (NSString *)currentHash
{
    NSData *fileData = [NSData dataWithContentsOfFile:_plistPath];
    if(fileData == nil) return nil;
    const uint8_t *bytes = fileData.bytes;
    uint64_t hash = 1469598103934665603ULL;
    for(NSUInteger i = 0; i < fileData.length; i++) {
        hash ^= bytes[i];
        hash *= 1099511628211ULL;
    }
    return [NSString stringWithFormat:@"%016llx", (unsigned long long)hash];
}

- (BOOL)reloadIfNeeded'''
s, n = re.subn(r'- \(NSString \*\)currentHash\s*\{.*?\n\}\s*\n- \(BOOL\)reloadIfNeeded', replacement, s, count=1, flags=re.S)
if n != 1: raise SystemExit('could not patch NXPlist currentHash')
p.write_text(s)
"""


def patch_nxplist(path):
    _run_patch(_PATCH_NXPLIST, path)


_PATCH_LDE_WORKSPACE_HOST = r"""from pathlib import Path
import re
p = Path(sys.argv[1])
s = p.read_text()
s = s.replace('#import <LindChain/Private/FoundationPrivate.h>\n', '')
pattern = re.compile(r'#if __has_include\(<Nyxian-Swift\.h>\).*?#endif /\* __has_include\(<Nyxian-Swift\.h>\) \*/', re.S)
replacement = '#define LIVEPROCESS 0\n#import <LindChain/ProcEnvironment/PELaunchServiceManager.h>\n#import <LindChain/ProcEnvironment/PEProcessManager.h>'
s, n = pattern.subn(replacement, s, count=1)
if n != 1: raise SystemExit('could not force host branch in LDEApplicationWorkspace.m')
if '#import <LindChain/ProcEnvironment/PEFileHandle.h>' not in s:
    s = s.replace('#import <LindChain/ProcEnvironment/PEArchiveHandle.h>\n', '#import <LindChain/ProcEnvironment/PEArchiveHandle.h>\n#import <LindChain/ProcEnvironment/PEFileHandle.h>\n')
p.write_text(s)
"""


def patch_lde_workspace_host(path):
    _run_patch(_PATCH_LDE_WORKSPACE_HOST, path)


_PATCH_LDE_WORKSPACE_CANONICAL_RETRY = r"""from pathlib import Path
p = Path(sys.argv[1])
s = p.read_text()
start = s.index('- (LDEApplicationObject*)applicationObjectForExecutablePath:(NSString*)executablePath')
end = s.index('\n- (NSString*)utilityHomePath', start)
new = r'''- (LDEApplicationObject*)applicationObjectForExecutablePath:(NSString*)executablePath
{
    if(executablePath.length == 0) return nil;

    NSMutableArray<NSString*> *candidates = [NSMutableArray arrayWithObject:executablePath];
    char canonicalPath[PATH_MAX];
    if(realpath(executablePath.fileSystemRepresentation, canonicalPath) != NULL)
    {
        NSString *canonical = [NSString stringWithUTF8String:canonicalPath];
        if(canonical.length && ![canonical isEqualToString:executablePath])
        {
            [candidates addObject:canonical];
        }
    }

    for(NSString *candidate in candidates)
    {
        [self connect];
        if(_connection == nil) continue;

        __block LDEApplicationObject *application = nil;
        __block BOOL failed = NO;
        dispatch_semaphore_t sema = dispatch_semaphore_create(0);
        id proxy = [_connection remoteObjectProxyWithErrorHandler:^(NSError *error) {
            failed = YES;
            dispatch_semaphore_signal(sema);
        }];
        if(proxy == nil)
        {
            failed = YES;
            dispatch_semaphore_signal(sema);
        }
        else
        {
            [proxy applicationObjectForExecutablePath:candidate withReply:^(LDEApplicationObject *applicationReply) {
                application = applicationReply;
                dispatch_semaphore_signal(sema);
            }];
        }

        long waited = dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)));
        if(waited == 0 && !failed && application != nil)
        {
            return application;
        }
        if(failed) [self disconnect];
    }
    return NXROMApplicationObjectForExecutablePath(executablePath);
}
'''
helper = r'''extern NSString *NXROMApplicationSourcePath(void);
static LDEApplicationObject *NXROMApplicationObjectForExecutablePath(NSString *executablePath)
{
    NSString *applications = [NXROMApplicationSourcePath() stringByResolvingSymlinksInPath];
    char canonicalPath[PATH_MAX];
    if(applications.length == 0 || realpath(executablePath.fileSystemRepresentation, canonicalPath) == NULL)
    {
        return nil;
    }
    NSString *canonical = [NSString stringWithUTF8String:canonicalPath];
    if([canonical hasPrefix:@"/var/"])
    {
        canonical = [@"/private" stringByAppendingString:canonical];
    }
    if(![canonical hasPrefix:[applications stringByAppendingString:@"/"]])
    {
        return nil;
    }
    for(NSString *bundlePath = canonical.stringByDeletingLastPathComponent;
        bundlePath.length > applications.length;
        bundlePath = bundlePath.stringByDeletingLastPathComponent)
    {
        if(![bundlePath.pathExtension isEqualToString:@"app"])
        {
            continue;
        }
        NSBundle *bundle = [NSBundle bundleWithPath:bundlePath];
        if(bundle.bundleIdentifier.length == 0 ||
           ![[bundle.executablePath stringByResolvingSymlinksInPath] isEqualToString:[canonical stringByResolvingSymlinksInPath]])
        {
            return nil;
        }
        return [[LDEApplicationObject alloc] initWithNSBundle:bundle];
    }
    return nil;
}

'''
s = s[:start] + new + s[end:]
marker = '@implementation LDEApplicationWorkspace'
if 'NXROMApplicationObjectForExecutablePath(NSString' not in s:
    if marker not in s:
        raise SystemExit('LDEApplicationWorkspace implementation not found')
    s = s.replace(marker, helper + marker, 1)
if '#include <limits.h>\n' not in s:
    s = s.replace('#import <os/lock.h>\n', '#import <os/lock.h>\n#include <limits.h>\n#include <stdlib.h>\n')
p.write_text(s)
"""


def patch_lde_workspace_canonical_retry(path):
    _run_patch(_PATCH_LDE_WORKSPACE_CANONICAL_RETRY, path)


_PATCH_BOOTSTRAPD_APPLICATION_READ = r"""from pathlib import Path
p = Path(sys.argv[1])
s = p.read_text()
needle = '''        /* sandbox */
        (__bridge NSString*)kNXT2EntitlementSandboxFileReadWrite: @[
'''
replacement = '''        /* sandbox */
        (__bridge NSString*)kNXT2EntitlementSandboxFileRead: @[
            @"$(NXROOT)/Application",
        ],
        (__bridge NSString*)kNXT2EntitlementSandboxFileReadWrite: @[
'''
if '@"$(NXROOT)/Application"' not in s:
    if needle not in s:
        raise SystemExit('bootstrapd sandbox preset anchor not found')
    s = s.replace(needle, replacement, 1)
p.write_text(s)
"""


def patch_bootstrapd_application_read(path):
    _run_patch(_PATCH_BOOTSTRAPD_APPLICATION_READ, path)


_PATCH_MOUNTED_APP_BUNDLE = r"""from pathlib import Path
p = Path(sys.argv[1])
s = p.read_text()
old = r'''        LDEApplicationObject *applicationObject = [[LDEApplicationWorkspace shared] applicationObjectForExecutablePath:(__bridge NSString*)executableString];
        if(applicationObject != nil && applicationObject.bundlePath != nil && applicationObject.containerPath != nil)
        {
            /* is a application bundle */
            vars[@"CONTAINER"] = applicationObject.containerPath;
            vars[@"BUNDLE"] = applicationObject.bundlePath;
        }
'''
new = r'''        NSString *executablePath = (__bridge NSString*)executableString;
        LDEApplicationObject *applicationObject = [[LDEApplicationWorkspace shared] applicationObjectForExecutablePath:executablePath];
        if(applicationObject.bundlePath.length > 0)
        {
            vars[@"BUNDLE"] = applicationObject.bundlePath;
        }
        if(applicationObject.containerPath.length > 0)
        {
            vars[@"CONTAINER"] = applicationObject.containerPath;
        }

        if(vars[@"BUNDLE"] == nil)
        {
            NSString *candidateBundle = [executablePath stringByDeletingLastPathComponent];
            if([[candidateBundle pathExtension] isEqualToString:@"app"])
            {
                vars[@"BUNDLE"] = candidateBundle;
            }
        }
'''
if old not in s: raise SystemExit('trust bundle anchor not found')
s=s.replace(old,new,1)
p.write_text(s)
"""


def patch_mounted_app_bundle(path):
    _run_patch(_PATCH_MOUNTED_APP_BUNDLE, path)


def patch_rom_application_mount(path):
    p = Path(path)
    s = p.read_text()
    if '#include <dlfcn.h>\n' not in s:
        if '#include <string.h>\n' not in s:
            raise SystemExit('fs.m: string.h include not found')
        s = s.replace('#include <string.h>\n', '#include <string.h>\n#include <dlfcn.h>\n', 1)

    helper = r'''/* the ROM slot's Application directory: beside the ROM's main image (the host path
 * behind the guests' /Application; NXMainSlot.m spawns the ROM's apps from it) */
NSString *NXROMApplicationSourcePath(void);
NSString *NXROMApplicationSourcePath(void)
{
    Dl_info info = {0};
    if(dladdr((const void *)&ksurface_fs_init, &info) == 0 || info.dli_fname == NULL)
    {
        return nil;
    }
    NSString *mainPath = [NSString stringWithUTF8String:info.dli_fname];
    if(mainPath.length == 0)
    {
        return nil;
    }
    NSString *path = [[[mainPath stringByDeletingLastPathComponent]
                       stringByAppendingPathComponent:@"Application"] stringByStandardizingPath];
    path = [path stringByResolvingSymlinksInPath];
    if([path hasPrefix:@"/var/"])
    {
        path = [@"/private" stringByAppendingString:path];
    }
    return path;
}

'''
    if 'NXROMApplicationSourcePath' not in s:
        marker = 'kern_return_t ksurface_fs_init(void)\n'
        if marker not in s:
            raise SystemExit('fs.m: ksurface_fs_init marker not found')
        s = s.replace(marker, helper + marker, 1)

    variables_end = '''    {
        kpanic("failed to initialize fs variable table");
    }
'''
    variables_extra = variables_end + '''
    /* ROM guest applications: the slot's immutable payload */
    NSString *romApplicationSource = NXROMApplicationSourcePath();
    if(romApplicationSource.length == 0 ||
       ![[NSFileManager defaultManager] fileExistsAtPath:romApplicationSource])
    {
        klog_log("ksurface:fs", "ROM Application source missing: %s",
                 romApplicationSource ? romApplicationSource.fileSystemRepresentation : "(null)");
        return KERN_NOT_FOUND;
    }
    if(ksurface_fs_mount3_var_add("romapps", romApplicationSource.fileSystemRepresentation) != KERN_SUCCESS)
    {
        kpanic("failed to initialize fs variable table");
    }
'''
    if 'romApplicationSource' not in s:
        if variables_end not in s:
            raise SystemExit('fs.m: fs variable table block not found')
        s = s.replace(variables_end, variables_extra, 1)

    vroot_mount = '    ksurface_fs_init_mount3(kFSMountAttrRead | kFSMountAttrWrite, FS_MOUNT_NOUNLINK, "$vroot");\n'
    mounts = vroot_mount + '''
    /* ROM guest applications: the slot's Application directory, read only at /Application.
     * The slot directory is a directory mount (FS_MOUNT_NOUNLINK) so the sandbox has a read
     * region backing it: guests are only issued tokens for paths inside directory mounts, and
     * the link's target canonicalizes to the slot. (Any other pseudo device, FS_MOUNT_SANDBOX
     * included, is a link target to mount3, and the preserver would displace the directory.) */
    ksurface_fs_init_mount3(kFSMountAttrRead, FS_MOUNT_NOUNLINK, "$romapps");
    ksurface_fs_init_mount3(kFSMountAttrRead, "$romapps", "$vroot/Application");
'''
    if '"$vroot/Application"' not in s:
        if vroot_mount not in s:
            raise SystemExit('fs.m: $vroot mount not found')
        s = s.replace(vroot_mount, mounts, 1)
    p.write_text(s)


_INCLUDE_GRAPH = r"""import os
import re
import shutil
from collections import defaultdict

REPO, OUT = map(os.path.realpath, sys.argv[1:3])
ROOT = os.path.join(REPO, "Nyxian")
SRCDIR = os.path.join(OUT, "rom", "src")
STUBDIR = os.path.join(OUT, "rom", "stubs")

SOURCE_ROOTS = [
    os.path.join(REPO, "LiveProcess"),
    os.path.join(REPO, "Nyxian"),
    os.path.join(REPO, "Frameworks", "LiveProcessLegacy"),
    os.path.join(REPO, "Frameworks", "libpatchfind"),
    REPO,
]
SOURCE_ROOTS = [r for r in SOURCE_ROOTS if os.path.isdir(r)]

FRAMEWORKS = {
    "LiveProcessLegacy": os.path.join(REPO, "Frameworks", "LiveProcessLegacy"),
}
FRAMEWORKS = {k: v for k, v in FRAMEWORKS.items() if os.path.isdir(v)}

inc_re = re.compile(r'#\s*(?:include|import)\s*([<"])([^>"]+)[>"]')
SOURCE_PREFIXES = ("LindChain/", "UI/", "Nyxian/", "Frameworks/")
FRAMEWORK_PREFIXES = tuple(name + "/" for name in FRAMEWORKS)
IN_TREE_PREFIXES = SOURCE_PREFIXES + FRAMEWORK_PREFIXES

framework_index = {}
for name, root in FRAMEWORKS.items():
    exact = {}
    by_base = defaultdict(list)
    by_suffix = defaultdict(list)
    for dp, _, fns in os.walk(root):
        for fn in fns:
            if not fn.endswith((".h", ".hpp")):
                continue
            full = os.path.realpath(os.path.join(dp, fn))
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            exact[rel] = full
            by_base[fn].append(full)
            parts = rel.split("/")
            for i in range(len(parts)):
                by_suffix["/".join(parts[i:])].append(full)
    framework_index[name] = (exact, by_base, by_suffix)

seen_real = set()
copied_virtual = set()
stubbed = set()
ambiguous = set()


def under(path, root):
    try:
        return os.path.commonpath([os.path.realpath(path), os.path.realpath(root)]) == os.path.realpath(root)
    except ValueError:
        return False


def source_virtual_path(real):
    real = os.path.realpath(real)
    for root in SOURCE_ROOTS:
        if under(real, root):
            return os.path.relpath(real, root).replace(os.sep, "/")
    return None


def framework_hit(inc):
    if "/" not in inc:
        return None
    fw, tail = inc.split("/", 1)
    if fw not in framework_index:
        return None
    exact, by_base, by_suffix = framework_index[fw]

    if tail in exact:
        return exact[tail]

    suffix_hits = list(dict.fromkeys(by_suffix.get(tail, [])))
    if len(suffix_hits) == 1:
        return suffix_hits[0]
    if len(suffix_hits) > 1:
        ambiguous.add(inc)
        return None

    base_hits = list(dict.fromkeys(by_base.get(os.path.basename(tail), [])))
    if len(base_hits) == 1:
        return base_hits[0]
    if len(base_hits) > 1:
        ambiguous.add(inc)
    return None


def resolve(inc, delim, including_real, including_virtual):
    cur_real_dir = os.path.dirname(including_real)
    cur_virtual_dir = os.path.dirname(including_virtual)

    if delim == '"':
        sib = os.path.realpath(os.path.join(cur_real_dir, inc))
        if os.path.isfile(sib) and sib != os.path.realpath(including_real):
            virt = os.path.normpath(os.path.join(cur_virtual_dir, inc)).replace(os.sep, "/")
            return sib, virt

    hit = framework_hit(inc)
    if hit:
        return hit, inc

    for root in SOURCE_ROOTS:
        candidate = os.path.realpath(os.path.join(root, inc))
        if os.path.isfile(candidate):
            return candidate, inc

    return None


def copy_and_walk(real, virtual):
    real = os.path.realpath(real)
    virtual = os.path.normpath(virtual).replace(os.sep, "/")
    if virtual.startswith("../") or virtual == "..":
        return

    dest = os.path.join(SRCDIR, *virtual.split("/"))
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if virtual not in copied_virtual:
        if not os.path.exists(dest):
            shutil.copy2(real, dest)
        copied_virtual.add(virtual)

    walk(real, virtual)


def make_stub(inc):
    if inc in stubbed or not inc.endswith((".h", ".hpp")):
        return
    stubbed.add(inc)
    dest = os.path.join(STUBDIR, *inc.split("/"))
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    guard = re.sub(r"[^A-Za-z0-9]", "_", inc).upper()
    with open(dest, "w") as f:
        f.write(
            f"/* AUTO-STUB for {inc}\n"
            "   No matching header exists in Nyxian/LiveProcess/Frameworks.\n"
            "   Fill in only the ABI surface this ROM actually needs. */\n"
            f"#ifndef {guard}\n#define {guard}\n#endif\n"
        )

def walk(real, virtual):
    real = os.path.realpath(real)
    key = (real, virtual)
    if key in seen_real or not os.path.isfile(real):
        return
    seen_real.add(key)

    try:
        text = open(real, "r", errors="ignore").read()
    except OSError:
        return

    for delim, inc in inc_re.findall(text):
        inc = inc.strip()

        is_prefixed = inc.startswith(IN_TREE_PREFIXES)
        resolved = resolve(inc, delim, real, virtual)

        if resolved:
            hit_real, hit_virtual = resolved
            copy_and_walk(hit_real, hit_virtual)
        elif is_prefixed:
            make_stub(inc)

seed_pairs = []
for component in ("LindChain/ProcEnvironment", "LindChain/WindowServer"):
    original = os.path.join(ROOT, component)
    if not os.path.isdir(original):
        continue
    for dp, _, fns in os.walk(original):
        for fn in fns:
            if not fn.endswith((".h", ".hpp", ".c", ".m", ".mm", ".cpp")):
                continue
            real = os.path.join(dp, fn)
            virtual = os.path.relpath(real, ROOT).replace(os.sep, "/")

            if (
                virtual.startswith("LindChain/ProcEnvironment/Shims/")
                or virtual.startswith("LindChain/ProcEnvironment/LiveContainer/Tweaks/")
            ):
                continue
            if virtual == "LindChain/ProcEnvironment/LiveContainer/LCBootstrap.m":
                continue

            if virtual == "LindChain/ProcEnvironment/Surface/cache/shimcache.m":
                continue

            if virtual in (
                "LindChain/WindowServer/Session/NXWindowSessionTerminal.m",
                "LindChain/WindowServer/Session/NXWindowSessionTerminal.h",
            ):
                continue

            seed_pairs.append((real, virtual))
            copied_virtual.add(virtual)

for real, virtual in seed_pairs:
    walk(real, virtual)

print(f"   visited {len(seen_real)} source/header nodes")
print(f"   materialized {len(copied_virtual)} in-tree files")
print(f"   stubbed {len(stubbed)} genuinely unresolved headers -> rom/stubs/")
for s in sorted(stubbed):
    print(f"     stub: {s}")
if ambiguous:
    print("   warning: ambiguous framework header names were not guessed:")
    for s in sorted(ambiguous):
        print(f"     ambiguous: {s}")
"""


def resolve_include_graph(repo, out):
    args = _PatchArgs(repo)
    args.argv = ['graph', str(repo), str(out)]
    exec(compile(_INCLUDE_GRAPH, '<include-graph>', 'exec'), {'__name__': '__graph__', 'sys': args})


MAKEFILE = r'''
SDK         := iphoneos
ARCH        := arm64
MIN_IOS     := 18.0
NAME        := main
SRCDIR      := rom/src
ZSIGNDIR    := $(SRCDIR)/LindChain/ProcEnvironment/LiveContainer/ZSign
INCDIRS     := -Irom/src -Irom/stubs -Irom/include -I$(ZSIGNDIR) -I$(ZSIGNDIR)/common
FWFLAGS     := -From/frameworks
CC          := $(shell xcrun -sdk $(SDK) -f clang)
LD          := $(shell xcrun -sdk $(SDK) -f clang++)
SYSROOT     := $(shell xcrun -sdk $(SDK) --show-sdk-path)

ROM_SIGNING_KEY ?= $(HOME)/.config/nyxian/romkey/rom.key.pem
ROM_OUT         ?= rom.zip
ROM_ZIP         := $(abspath $(patsubst ~/%,$(HOME)/%,$(ROM_OUT)))
ROM_KEY         := $(patsubst ~/%,$(HOME)/%,$(ROM_SIGNING_KEY))
ifneq ($(words $(ROM_OUT)),1)
$(error ROM_OUT cannot contain spaces (make splits paths on them): "$(ROM_OUT)")
endif

HELLO_SRC   := appsrc/Hello/main.m
HELLO_PLIST := appsrc/Hello/Info.plist
HELLO_APP   := Application/Hello.app
HELLO_BIN   := $(HELLO_APP)/Hello

SRCS_ALL    := $(shell find $(SRCDIR) \( -name '*.m' -o -name '*.c' -o -name '*.mm' -o -name '*.cpp' \))
SRCS        := $(filter-out \
               $(SRCDIR)/LindChain/ProcEnvironment/Shims/% \
               $(SRCDIR)/LindChain/ProcEnvironment/LiveContainer/Tweaks/% \
               $(SRCDIR)/LindChain/ProcEnvironment/LiveContainer/LCBootstrap.m, \
               $(SRCS_ALL))
OBJS        := $(SRCS:%=build/%.o)

CFLAGS      := -arch $(ARCH) -isysroot $(SYSROOT) -miphoneos-version-min=$(MIN_IOS) \
               -fobjc-arc -O2 -g -DHOST_ENV=1 -Wno-nonportable-include-path $(INCDIRS)
LDFLAGS     := -arch $(ARCH) -isysroot $(SYSROOT) -miphoneos-version-min=$(MIN_IOS) \
               -dynamiclib -install_name @rpath/$(NAME) \
               -rpath @executable_path/Frameworks $(FWFLAGS) \
               -framework Foundation -framework UIKit -framework CoreFoundation \
               -framework CoreGraphics -framework QuartzCore -framework Security \
               -framework FrontBoard -framework OpenSSL -larchive
HELLO_FLAGS := -arch $(ARCH) -isysroot $(SYSROOT) -miphoneos-version-min=$(MIN_IOS) \
               -fobjc-arc -Os -framework Foundation -framework UIKit

all: $(ROM_ZIP)

build/%.o: %
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(if $(filter %.cpp,$<),-x c++,$(if $(filter %.mm,$<),-x objective-c++)) -c $< -o $@

$(NAME): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(NAME)

$(HELLO_BIN): $(HELLO_SRC) $(HELLO_PLIST)
	rm -rf $(HELLO_APP)
	mkdir -p $(HELLO_APP)
	cp $(HELLO_PLIST) $(HELLO_APP)/Info.plist
	$(CC) $(HELLO_FLAGS) -dynamiclib -Wl,-install_name,@rpath/Hello $(HELLO_SRC) -o $(HELLO_BIN)

$(ROM_ZIP): $(NAME) $(HELLO_BIN) manifest.plist
	@test -f "$(ROM_KEY)" || { echo "no ROM signing key at $(ROM_KEY): python3 RomGen.py genkey --name rom, or make ROM_SIGNING_KEY=..."; exit 1; }
	@case "$(ROM_ZIP)" in *.zip) ;; *) echo "ROM_OUT has to end in .zip: $(ROM_ZIP)"; exit 1;; esac
	rm -rf .rompkg "$(ROM_ZIP)"
	mkdir -p .rompkg/ROM "$(dir $(ROM_ZIP))"
	cp $(NAME) manifest.plist .rompkg/ROM/
	cp -R Application .rompkg/ROM/Application
	cd .rompkg && zip -qry -X "$(ROM_ZIP)" ROM -x '*.DS_Store' '*/._*'
	rm -rf .rompkg
	python3 -I RomGen.py sign "$(ROM_ZIP)" --key "$(ROM_KEY)"
	@echo "ROM: $(ROM_ZIP)"

clean:
	rm -rf build .rompkg Application $(NAME) rom.zip

.PHONY: all clean
'''

README = r'''# Nyxian ROM skeleton

Generated by `RomGen.py generate` (revision @REV@) from a Nyxian checkout.

## Build

    python3 RomGen.py genkey --name rom      # once: your release key (keep rom.key.pem private)
    make                                     # rom.zip, signed with ~/.config/nyxian/romkey/rom.key.pem
    make ROM_OUT=$HOME/Desktop/MyROM-1.0.zip # the signed ZIP somewhere else
    make ROM_SIGNING_KEY=$HOME/.config/nyxian/romkey/other.key.pem   # another key
    make clean

Send `~/.config/nyxian/romkey/rom.pub.pem` and the ROM's `NXRomIdentifier` (@IDENTIFIER@) to emexLabs:
Nyxian only boots ROMs whose release key is in its TrustStore. Check a build with

    python3 RomGen.py verify rom.zip --truststore online

## Layout

- `manifest.plist`: the ROM manifest. Raise `NXRomSecurityVersion` with every release (Nyxian never
  goes back to a lower one); every executable needs an `NXRomPaths` entry with `NXRequiresCodeSigning`.
- `rom/src`: the kernel surface and window server from Nyxian, `NXMainSlot.m` is the slot entry
  (`NXSlotMain`, `NXSlotCreateWindow`, `NXSlotDidAppear`).
- `appsrc/Hello`: a guest app, shipped in `Application/` and mounted at `/Application`.
'''

MANIFEST = r'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>NXRomManifestVersion</key>
    <integer>1</integer>

    <key>NXRomIdentifier</key>
    <string>@IDENTIFIER@</string>
    <key>NXRomName</key>
    <string>@NAME@</string>
    <key>NXRomVersion</key>
    <string>1.0</string>

    <key>NXRomSecurityVersion</key>
    <integer>1</integer>
    <key>NXRomMinimumNyxianVersion</key>
    <string>@MIN_NYXIAN@</string>

    <key>NXRomDefaultFilePermission</key>
    <integer>420</integer>
    <key>NXRomDefaultDirectoryPermission</key>
    <integer>493</integer>

    <key>NXRomPaths</key>
    <array>

        <dict>
            <key>NXPath</key>
            <string>main</string>
            <key>NXPermission</key>
            <integer>365</integer>
            <key>NXRequiresCodeSigning</key>
            <true/>
        </dict>

        <dict>
            <key>NXPath</key>
            <string>Application/Hello.app/Hello</string>
            <key>NXPermission</key>
            <integer>365</integer>
            <key>NXRequiresCodeSigning</key>
            <true/>
            <key>NXT2Entitlements</key>
            <dict>
                <key>org.emexlabs.nyxian.platform</key>
                <true/>
                <key>org.emexlabs.nyxian.platform.user</key>
                <integer>501</integer>
                <key>org.emexlabs.nyxian.platform.group</key>
                <integer>501</integer>
                <key>org.emexlabs.nyxian.get-task-allow</key>
                <false/>
            </dict>
        </dict>
    </array>

    <key>NXRomExecutable</key>
    <string>main</string>
</dict>
</plist>
'''


def log(message):
    print(f'>> {message}')


def nyxian_version(repo):
    config = repo / 'Config.xcconfig'
    if config.exists():
        match = re.search(r'^\s*VERSION\s*=\s*([0-9][0-9.]*)', config.read_text(), re.M)
        if match:
            return match.group(1)
    return None


def remove(path):
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def generate_signing_key(given):
    if given:
        key = Path(given).expanduser().resolve()
        if not key.is_file():
            fail(f'no key at {key} (python3 RomGen.py genkey --name NAME)')
        if b'PRIVATE KEY' not in key.read_bytes()[:200]:
            fail(f'{key} is not a private key (sign with NAME.key.pem, not NAME.pub.pem)')
        return key, []
    keys = sorted(KEY_DIR.glob('*.key.pem')) if KEY_DIR.is_dir() else []
    if KEY_DIR / 'rom.key.pem' in keys:
        return (KEY_DIR / 'rom.key.pem').resolve(), []
    if len(keys) == 1:
        return keys[0].resolve(), []
    return None, keys


def command_generate(args):
    source = Path(args.nyxian).resolve()
    if (source / 'Nyxian/LindChain/ProcEnvironment').is_dir():
        repo = source
    elif (source / 'LindChain/ProcEnvironment').is_dir():
        repo = source.parent
    else:
        fail(f'could not locate LindChain/ProcEnvironment under {source}')
    if not identifier_valid(args.identifier):
        fail(f'{args.identifier} is not a valid NXRomIdentifier (reverse DNS, like com.vendor.rom)')
    root = repo / 'Nyxian'
    pe = root / 'LindChain/ProcEnvironment'
    out = Path(args.out).resolve()
    if out == repo or out in repo.parents or out == Path.home().resolve():
        fail(f'{out} would replace the Nyxian checkout or your home, give a new directory')
    if out.exists() and any(out.iterdir()) and not ((out / 'rom/src').is_dir() and (out / 'Makefile').is_file()) and not args.force:
        fail(f'{out} is not empty and not a generated template, it would be replaced (--force)')
    signing_key, other_keys = generate_signing_key(args.key)
    minimum = args.min_nyxian or nyxian_version(repo)
    if not minimum:
        fail('could not read the Nyxian version from Config.xcconfig, give --min-nyxian')

    log(f'generator revision: {GEN_ROM_REV}')
    log(f'output: {out}')
    if out.exists():
        remove(out)
    src = out / 'rom/src'
    for directory in ('rom/src', 'rom/stubs', 'rom/include', 'rom/frameworks'):
        (out / directory).mkdir(parents=True, exist_ok=True)

    log('copying ProcEnvironment')
    (src / 'LindChain').mkdir(parents=True, exist_ok=True)
    shutil.copytree(pe, src / 'LindChain/ProcEnvironment', symlinks=True)

    for guest in ('Shims', 'LiveContainer/Tweaks'):
        directory = src / 'LindChain/ProcEnvironment' / guest
        if directory.is_dir():
            for path in directory.rglob('*'):
                if path.is_file() and path.suffix in ('.m', '.mm', '.c', '.cpp'):
                    path.unlink()
    (src / 'LindChain/ProcEnvironment/LiveContainer/LCBootstrap.m').unlink(missing_ok=True)
    log('excluding guest sources: ProcEnvironment/Shims, LiveContainer/Tweaks, LiveContainer/LCBootstrap.m')

    peprocess = src / 'LindChain/ProcEnvironment/PEProcess.m'
    if peprocess.is_file():
        patch_mdk_import(peprocess)
    shimcache = src / 'LindChain/ProcEnvironment/Surface/cache/shimcache.m'
    if shimcache.is_file():
        shimcache.write_text(SHIMCACHE_M)
    log('excluding MobileDevelopmentKit and the MDK backed host shim compiler')

    if (root / 'LindChain/WindowServer').is_dir():
        shutil.copytree(root / 'LindChain/WindowServer', src / 'LindChain/WindowServer', symlinks=True)
        for name in ('NXWindowSessionTerminal.m', 'NXWindowSessionTerminal.h'):
            (src / 'LindChain/WindowServer/Session' / name).unlink(missing_ok=True)

    for header in ('ksurface_abi.h', 'ksurface_config.h'):
        if (repo / header).is_file():
            shutil.copy2(repo / header, out / 'rom/include' / header)
    boot_args = (repo / 'BootHandoff/NXBootArgs.h').is_file()
    if boot_args:
        shutil.copy2(repo / 'BootHandoff/NXBootArgs.h', out / 'rom/include/NXBootArgs.h')

    for host_objc in ('PEProcessManager.m', 'PEUserspaceManager.m'):
        path = src / 'LindChain/ProcEnvironment' / host_objc
        if path.is_file():
            patch_swift_import(path)
    (out / 'rom/include/Nyxian-Swift.h').unlink(missing_ok=True)
    peum = src / 'LindChain/ProcEnvironment/PEUserspaceManager.m'
    if peum.is_file():
        patch_peum_imports(peum)

    presenter = root / 'LindChain/IDEFoundation/NXAlertDiagnosticPresenter'
    if presenter.with_suffix('.h').is_file() and presenter.with_suffix('.m').is_file():
        (src / 'LindChain/IDEFoundation').mkdir(parents=True, exist_ok=True)
        for suffix in ('.h', '.m'):
            shutil.copy2(presenter.with_suffix(suffix), src / 'LindChain/IDEFoundation' / ('NXAlertDiagnosticPresenter' + suffix))

    openssl_framework = root / 'LindChain/OpenSSL.xcframework/ios-arm64/OpenSSL.framework'
    if (pe / 'LiveContainer/ZSign').is_dir():
        if not openssl_framework.is_dir():
            fail(f'ZSign is present but the iOS arm64 OpenSSL.framework was not found: {openssl_framework}')
        log('copying OpenSSL iOS arm64 framework')
        shutil.copytree(openssl_framework, out / 'rom/frameworks/OpenSSL.framework', symlinks=True)
        shutil.copytree(openssl_framework / 'Headers', out / 'rom/include/openssl')
        if not (out / 'rom/include/OpenSSL').exists():
            os.symlink('openssl', out / 'rom/include/OpenSSL')
        if not (out / 'rom/include/openssl/ocsp.h').is_file():
            fail('OpenSSL header staging failed (ocsp.h missing)')

    frontboard = root / 'LindChain/Private/Frameworks/FrontBoard.framework'
    if not frontboard.is_dir():
        fail(f'FrontBoard.framework link stub not found: {frontboard}')
    log('staging FrontBoard link stub')
    shutil.copytree(frontboard, out / 'rom/frameworks/FrontBoard.framework', symlinks=True)

    log('resolving include graph')
    resolve_include_graph(str(repo), str(out))

    for directory in ('LindChain/IDEFoundation', 'LindChain/Utils', 'LindChain/Services/bootstrapd', 'ROMCompat'):
        (src / directory).mkdir(parents=True, exist_ok=True)

    nxplist = root / 'LindChain/IDEFoundation/NXPlist.m'
    if nxplist.is_file():
        shutil.copy2(nxplist, src / 'LindChain/IDEFoundation/NXPlist.m')
        patch_nxplist(src / 'LindChain/IDEFoundation/NXPlist.m')
    if (root / 'LindChain/Utils/Zip.m').is_file():
        shutil.copy2(root / 'LindChain/Utils/Zip.m', src / 'LindChain/Utils/Zip.m')

    workspace = repo / 'Frameworks/LiveProcessLegacy/LindChain/Services/bootstrapd/LDEApplicationWorkspace.m'
    if not workspace.is_file():
        fail(f'LDEApplicationWorkspace.m not found: {workspace}')
    else:
        target = src / 'LindChain/Services/bootstrapd/LDEApplicationWorkspace.m'
        shutil.copy2(workspace, target)
        patch_lde_workspace_host(target)
        patch_lde_workspace_canonical_retry(target)
    (src / 'LindChain/Services/bootstrapd/LDEApplicationObject.m').write_text(LDE_APPLICATION_OBJECT_M)
    (src / 'ROMCompat/CCCompat.c').write_text(CCCOMPAT_C)

    fs = src / 'LindChain/ProcEnvironment/Surface/fs/fs.m'
    if fs.is_file():
        patch_rom_application_mount(fs)
    presets = src / 'LindChain/ProcEnvironment/Surface/trust/presets.m'
    if presets.is_file():
        patch_bootstrapd_application_read(presets)
    trust = src / 'LindChain/ProcEnvironment/Surface/trust/trust.m'
    if trust.is_file():
        patch_mounted_app_bundle(trust)

    sources = [path for path in src.rglob('*') if path.is_file() and path.suffix in ('.h', '.m', '.c', '.mm')]
    if any('PEServiceProtocol' in path.read_text(errors='ignore') for path in sources) and \
       not any(re.search(r'@protocol\s+PEServiceProtocol', path.read_text(errors='ignore')) for path in sources):
        fail('PEServiceProtocol is used but was not resolved from Frameworks/LiveProcessLegacy (ServiceKit/LPLServiceProtocol.h)')

    (src / 'LindChain/IDEFoundation/NXBootstrap.h').write_text(NXBOOTSTRAP_H)
    (src / 'LindChain/IDEFoundation/NXBootstrap.m').write_text(NXBOOTSTRAP_M)
    (out / 'appsrc/Hello').mkdir(parents=True, exist_ok=True)
    (out / 'appsrc/Hello/main.m').write_text(HELLO_MAIN_M)
    (out / 'appsrc/Hello/Info.plist').write_text(HELLO_INFO_PLIST)
    (src / 'NXMainSlot.m').write_text(nxmainslot_with_boot_args(NXMAINSLOT_M) if boot_args else NXMAINSLOT_M)
    if boot_args:
        log('boot arguments: NXMainSlot.m reads them through rom/include/NXBootArgs.h (old keys on 0.11.6.1)')

    makefile = MAKEFILE
    if signing_key:
        home = Path.home().resolve()
        shown = f'$(HOME)/{signing_key.relative_to(home)}' if home in signing_key.parents else str(signing_key)
        makefile = makefile.replace('ROM_SIGNING_KEY ?= $(HOME)/.config/nyxian/romkey/rom.key.pem',
                                    f'ROM_SIGNING_KEY ?= {shown}')
    (out / 'Makefile').write_text(makefile)
    (out / 'manifest.plist').write_text(MANIFEST.replace('@IDENTIFIER@', args.identifier)
                                        .replace('@NAME@', args.name.replace('&', '&amp;').replace('<', '&lt;'))
                                        .replace('@MIN_NYXIAN@', minimum))
    plistlib.loads((out / 'manifest.plist').read_bytes())
    readme = README.replace('@REV@', GEN_ROM_REV).replace('@IDENTIFIER@', args.identifier)
    if boot_args:
        readme += ('- `rom/include/NXBootArgs.h`: the boot arguments (Settings > General > Boot Arguments, bootloader\n'
                   '  0.11.6.2+), `NXMainSlot.m` reads `-x` and `klog_obfuscate` from them; old keys on 0.11.6.1.\n')
    (out / 'README.md').write_text(readme)
    shutil.copy2(Path(__file__).resolve(), out / 'RomGen.py')
    log(f'done: {args.name} ({args.identifier}), minimum Nyxian {minimum}')
    if signing_key:
        log(f'next: cd {out} && make   (signs with {signing_key})')
    elif other_keys:
        log(f'next: cd {out} && make ROM_SIGNING_KEY=<one of: {", ".join(str(k) for k in other_keys)}>')
        log(f'      (or generate again with --key to make one the default)')
    else:
        log('next: python3 RomGen.py genkey --name rom   (your release key, once for all your ROMs; send emexLabs rom.pub.pem)')
        log(f'      then cd {out} && make')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest='command', required=True)
    generate = commands.add_parser('generate', help='bake a ROM template from a Nyxian checkout')
    generate.add_argument('nyxian', help='the Nyxian checkout')
    generate.add_argument('out', help='the template directory (replaced)')
    generate.add_argument('--identifier', default='com.example.rom', help='NXRomIdentifier (reverse DNS)')
    generate.add_argument('--name', default='Example ROM', help='NXRomName')
    generate.add_argument('--min-nyxian', help='NXRomMinimumNyxianVersion (default: the checkout\'s version)')
    generate.add_argument('--force', action='store_true', help='replace a non-empty directory that is not a template')
    generate.add_argument('--key', help=f'the private key make signs with (default: the only one, or rom, in {KEY_DIR})')
    generate.set_defaults(run=command_generate)
    genkey = commands.add_parser('genkey', help='create your ROM signing key pair')
    genkey.add_argument('--name', default='rom', help='file name for the key (default rom)')
    genkey.add_argument('--out', default=str(KEY_DIR), help=f'directory (default {KEY_DIR})')
    genkey.set_defaults(run=command_genkey)
    public = commands.add_parser('public', help='print the public key of a private key')
    public.add_argument('key')
    public.set_defaults(run=command_public)
    sign = commands.add_parser('sign', help='sign a ROM ZIP (in place)')
    sign.add_argument('archive')
    sign.add_argument('--key', required=True, help='your private key (NAME.key.pem)')
    sign.set_defaults(run=command_sign)
    verify = commands.add_parser('verify', help='check a signed ROM ZIP')
    verify.add_argument('archive')
    verify.add_argument('--public', help='a public key (PEM or DER)')
    verify.add_argument('--truststore', help='a TrustStore file, or "online" for the published one')
    verify.set_defaults(run=command_verify)
    prove = commands.add_parser('prove', help="sign the Developer Portal's code to prove a key is yours")
    prove.add_argument('code', help='the code the portal shows')
    prove.add_argument('--key', required=True, help='your private key (NAME.key.pem)')
    prove.set_defaults(run=command_prove)
    digest = commands.add_parser('digest', help="the release digest the Developer Portal's TSS signs installs for")
    digest.add_argument('archive')
    digest.set_defaults(run=command_digest)
    info = commands.add_parser('info', help='show a ROM ZIP or a key')
    info.add_argument('file')
    info.set_defaults(run=command_info)
    args = parser.parse_args()
    try:
        args.run(args)
    except (OSError, ValueError, KeyError, plistlib.InvalidFileException, zipfile.BadZipFile) as error:
        fail(str(error))


if __name__ == '__main__':
    main()
