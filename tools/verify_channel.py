#!/usr/bin/env python3
"""Verify a static signed pacman channel with an out-of-band publisher pin.

No host keyring, package configuration, package installation or HID access.
This standalone verifier is also copied to the clean deployment workspace.
"""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import ssl
import subprocess
import tarfile
import tempfile
import urllib.parse
import urllib.request

MAX_FILE = 128 * 1024 * 1024
MAX_FILES = 64
VERSION = r'[0-9]+\.[0-9]+\.[0-9]+-[1-9][0-9]*'


class ChannelError(ValueError):
    pass


def fingerprint(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Fa-f0-9]{40}', value):
        raise ChannelError('An explicit full primary-key fingerprint is required')
    return value.upper()


def base_url(value):
    if not isinstance(value, str):
        raise ChannelError('An explicit HTTPS base URL is required')
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or '%' in parsed.path
            or any(part in ('.', '..') for part in parsed.path.split('/'))):
        raise ChannelError('Use a canonical HTTPS base URL without credentials or query')
    return value.rstrip('/') + '/'


def relative_name(name):
    if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_./-]+', name)
            or name.startswith('/') or '//' in name
            or any(p in ('.', '..') for p in name.split('/'))):
        raise ChannelError('Unsafe channel filename')
    return name


def run(argv, **kwargs):
    try:
        result = subprocess.run(argv, capture_output=True, timeout=60, **kwargs)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ChannelError('Required verification tool failed or timed out') from error
    if result.returncode:
        raise ChannelError('Cryptographic or package-tool verification failed')
    return result.stdout


def read_file(root, name, limit=MAX_FILE):
    relative_name(name)
    root = Path(root).absolute()
    if root.resolve(strict=True) != root or not root.is_dir():
        raise ChannelError('Channel root must be an ordinary directory without symlink parents')
    path = root / name
    if (path.is_symlink() or path.resolve(strict=True) != path.absolute() or not path.is_file()
            or path.stat().st_nlink != 1):
        raise ChannelError('Channel inputs must be ordinary files without symlink parents')
    if path.stat().st_size > limit:
        raise ChannelError('Channel file exceeds its size limit')
    return path.read_bytes()


def json_object(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ChannelError('Duplicate manifest key')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ChannelError('Invalid channel manifest') from error


def validate_status(raw, expected):
    lines = raw.decode('utf-8', errors='replace').splitlines()
    codes = [line.split()[1:] for line in lines if line.startswith('[GNUPG:] ')]
    denied = {'BADSIG', 'ERRSIG', 'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'KEYEXPIRED',
              'SIGEXPIRED', 'KEYREVOKED', 'NO_PUBKEY', 'FAILURE', 'NODATA'}
    if any(row and row[0] in denied for row in codes):
        raise ChannelError('Invalid, expired, revoked or missing signing key/signature')
    valid = [row[1:] for row in codes if row and row[0] == 'VALIDSIG']
    if len(valid) != 1 or len(valid[0]) not in (9, 10):
        raise ChannelError('Exactly one valid OpenPGP signature is required')
    fields = valid[0]
    primary = fields[9] if len(fields) == 10 else fields[0]
    if fingerprint(primary) != expected or fields[7] not in ('8', '9', '10'):
        raise ChannelError('Publisher fingerprint or signature digest is not permitted')


class PublicVerifier:
    def __init__(self, key_bytes, expected, home):
        self.expected = fingerprint(expected)
        self.home = Path(home)
        self.home.mkdir(mode=0o700)
        self.prefix = ['gpg', '--homedir', str(self.home), '--batch', '--no-auto-key-retrieve',
                       '--no-auto-key-import', '--auto-key-locate', 'clear']
        shown = run([*self.prefix, '--with-colons', '--import-options', 'show-only', '--import'], input=key_bytes)
        primaries = []
        awaiting = False
        for line in shown.decode().splitlines():
            fields = line.split(':')
            if fields[0] in ('sec', 'ssb'):
                raise ChannelError('Secret key material cannot enter a channel')
            if fields[0] == 'pub':
                awaiting = True
            elif fields[0] == 'fpr' and awaiting:
                primaries.append(fields[9]); awaiting = False
        if primaries != [self.expected]:
            raise ChannelError('Public key does not match the independently pinned publisher')
        run([*self.prefix, '--import'], input=key_bytes)

    def verify(self, signature, payload):
        status = run([*self.prefix, '--status-fd', '1', '--verify', str(signature), str(payload)])
        validate_status(status, self.expected)


def inspect_manifest(raw, expected):
    manifest = json_object(raw)
    keys = {'schema', 'package', 'version', 'architecture', 'base_url', 'fingerprint', 'files'}
    if not isinstance(manifest, dict) or set(manifest) != keys:
        raise ChannelError('Unsupported manifest schema')
    if (type(manifest['schema']) is not int or manifest['schema'] != 1
            or manifest['package'] != 'darmoshark-linux' or manifest['architecture'] != 'x86_64'
            or not isinstance(manifest['version'], str) or not re.fullmatch(VERSION, manifest['version'])
            or fingerprint(manifest['fingerprint']) != fingerprint(expected)):
        raise ChannelError('Channel identity or version is invalid')
    if base_url(manifest['base_url']) != manifest['base_url']:
        raise ChannelError('Manifest base URL must be canonical')
    files = manifest['files']
    if not isinstance(files, dict) or not 1 <= len(files) <= MAX_FILES:
        raise ChannelError('Invalid channel inventory')
    for name, record in files.items():
        relative_name(name)
        if (not isinstance(record, dict) or set(record) != {'sha256', 'size'}
                or not isinstance(record['sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', record['sha256'])
                or type(record['size']) is not int or not 0 <= record['size'] <= MAX_FILE):
            raise ChannelError('Invalid file integrity record')
    if sum(record['size'] for record in files.values()) > 256*1024*1024:
        raise ChannelError('Channel inventory exceeds its total size limit')
    required = {'publisher.asc', 'pacman.conf.in', 'arch/x86_64/darmoshark.db',
                'arch/x86_64/darmoshark.db.sig', 'arch/x86_64/darmoshark.db.tar.gz',
                'arch/x86_64/darmoshark.db.tar.gz.sig'}
    package = 'arch/x86_64/darmoshark-linux-' + manifest['version'] + '-any.pkg.tar.zst'
    if not required | {package, package+'.sig'} <= set(files):
        raise ChannelError('Channel lacks a signed database or current package')
    allowed = re.compile(r'arch/x86_64/(?:darmoshark\.(?:db|files)(?:\.tar\.gz)?(?:\.sig)?|darmoshark-linux-'+VERSION+r'-any\.pkg\.tar\.zst(?:\.sig)?)')
    if any(name not in ('publisher.asc', 'pacman.conf.in') and not allowed.fullmatch(name) for name in files):
        raise ChannelError('Unapproved channel file type')
    return manifest


def verify_database(root, manifest):
    with tarfile.open(fileobj=io.BytesIO(read_file(root, 'arch/x86_64/darmoshark.db'))) as archive:
        members = archive.getmembers()
        entries = [m for m in members if m.isfile()]
        if (len(members) > 4 or len(entries) != 1 or not entries[0].name.endswith('/desc')
                or entries[0].size > 65536 or any(not (m.isdir() or m.isfile()) for m in members)):
            raise ChannelError('Unsupported repository database structure')
        text = archive.extractfile(entries[0]).read().decode('utf-8')
    records = {}
    for block in text.strip().split('\n\n'):
        lines = block.splitlines()
        if not lines or lines[0] in records:
            raise ChannelError('Malformed database fields')
        records[lines[0]] = lines[1:]
    name = 'darmoshark-linux-'+manifest['version']+'-any.pkg.tar.zst'
    for key, value in (('%NAME%', 'darmoshark-linux'), ('%VERSION%', manifest['version']),
                       ('%FILENAME%', name), ('%ARCH%', 'any'),
                       ('%SHA256SUM%', manifest['files']['arch/x86_64/'+name]['sha256'])):
        if records.get(key) != [value]:
            raise ChannelError('Signed database does not index the selected package/version')
    # Current repo-add omits PGPSIG and pacman fetches the detached package .sig.
    # Older databases can embed it; if present it must match the verified file.
    if '%PGPSIG%' in records and records['%PGPSIG%'] != [base64.b64encode(read_file(root, 'arch/x86_64/'+name+'.sig')).decode('ascii')]:
        raise ChannelError('Database embedded package signature differs from its published signature')


def verify_local(root, expected, expected_url=None):
    root = Path(root)
    raw = read_file(root, 'channel.json', 256*1024)
    manifest = inspect_manifest(raw, expected)
    if expected_url is not None and manifest['base_url'] != base_url(expected_url):
        raise ChannelError('Signed channel URL differs from the approved deployment endpoint')
    inventory = set(manifest['files']) | {'channel.json', 'channel.json.sig'}
    actual = set()
    directories = 0
    for path in root.rglob('*'):
        if path.is_symlink():
            raise ChannelError('Static publishing cannot contain links')
        if path.is_dir():
            directories += 1
        else:
            actual.add(path.relative_to(root).as_posix())
        if len(actual) > MAX_FILES+2 or directories > 128:
            raise ChannelError('Unbounded channel directory inventory')
    if actual != inventory:
        raise ChannelError('Unlisted or missing channel files')
    for name, record in manifest['files'].items():
        content = read_file(root, name)
        if len(content) != record['size'] or hashlib.sha256(content).hexdigest() != record['sha256']:
            raise ChannelError('Channel file checksum/size mismatch')
    read_file(root, 'channel.json.sig', 16384)
    with tempfile.TemporaryDirectory(prefix='darmoshark-channel-verify-') as tmp:
        verifier = PublicVerifier(read_file(root, 'publisher.asc', 65536), expected, Path(tmp)/'gpg')
        verifier.verify(root/'channel.json.sig', root/'channel.json')
        for name in sorted(inventory):
            if name.endswith('.sig') and name != 'channel.json.sig':
                if name[:-4] not in inventory:
                    raise ChannelError('Detached signature has no payload')
                verifier.verify(root/name, root/name[:-4])
        packages = [name for name in inventory if name.endswith('.pkg.tar.zst')]
        for name in packages:
            if name+'.sig' not in inventory:
                raise ChannelError('Every retained package must be signed')
        if read_file(root, 'arch/x86_64/darmoshark.db') != read_file(root, 'arch/x86_64/darmoshark.db.tar.gz'):
            raise ChannelError('Repository database aliases conflict')
        verify_database(root, manifest)
    return manifest


class _SameOrigin(urllib.request.HTTPRedirectHandler):
    def __init__(self, origin):
        self.origin = origin

    def redirect_request(self, request, fp, code, message, headers, url):
        base_url(url)
        if not url.startswith(self.origin):
            raise ChannelError('Channel redirected outside its approved HTTPS base')
        return super().redirect_request(request, fp, code, message, headers, url)


def verify_remote(url, expected, output, *, tls_context=None):
    origin = base_url(url)
    output = Path(output).absolute()
    if output.parent.resolve(strict=True) != output.parent:
        raise ChannelError('Download output cannot have symlink parents')
    output.mkdir(exist_ok=False)
    if tls_context is not None and (not tls_context.check_hostname or tls_context.verify_mode != ssl.CERT_REQUIRED):
        raise ChannelError('TLS certificate and hostname verification cannot be disabled')
    opener = urllib.request.build_opener(_SameOrigin(origin), urllib.request.HTTPSHandler(context=tls_context))
    def fetch(name, limit):
        relative_name(name)
        request = urllib.request.Request(origin+name, headers={'User-Agent': 'Darmoshark-channel-verifier/1'})
        with opener.open(request, timeout=30) as response:
            if not response.geturl().startswith(origin):
                raise ChannelError('Unexpected remote channel origin')
            data = response.read(limit+1)
        if len(data) > limit:
            raise ChannelError('Remote file exceeds bounded download limit')
        target = output/name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
        return data
    raw = fetch('channel.json', 256*1024)
    manifest = inspect_manifest(raw, expected)
    if manifest['base_url'] != origin:
        raise ChannelError('Signed channel URL does not match the selected endpoint')
    fetch('channel.json.sig', 16384); fetch('publisher.asc', 65536)
    with tempfile.TemporaryDirectory(prefix='darmoshark-channel-origin-') as tmp:
        verifier = PublicVerifier(read_file(output, 'publisher.asc'), expected, Path(tmp)/'gpg')
        verifier.verify(output/'channel.json.sig', output/'channel.json')
    for name, record in manifest['files'].items():
        if name != 'publisher.asc':
            fetch(name, record['size'])
    return verify_local(output, expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--directory', type=Path); source.add_argument('--url')
    parser.add_argument('--fingerprint', required=True)
    parser.add_argument('--base-url', help='Expected deployment URL for local CI verification')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        if args.url:
            if args.output is None:
                raise ChannelError('Remote verification needs a new explicit download directory')
            result = verify_remote(args.url, args.fingerprint, args.output)
        else:
            result = verify_local(args.directory, args.fingerprint, args.base_url)
    except ChannelError as error:
        parser.exit(1, f'Channel verification refused: {error}\n')
    except (OSError, ValueError, tarfile.TarError):
        parser.exit(1, 'Channel verification refused: invalid or unavailable channel data\n')
    print(f'Verified signed channel {result["version"]}; no host trust or package changes')


if __name__ == '__main__':
    main()
