# Darmoshark Linux packages

Signed pacman distribution artifacts for the native Qt Linux utility. Application
source is included inside the Python packages under the MIT license. The private
development repository and its history are not copied into this repository.

## Publisher

Primary OpenPGP fingerprint:

`973409058934AA235ED54A12DF33A981D4B4332F`

The private signing key stays with the publisher; GitHub Actions only verifies
and deploys already-signed files. The independent Actions fingerprint pin is
configured separately from the signed inventory. Both package and database
signatures are mandatory. Never disable signature checks to install a package.

Channel base: https://existye4t.github.io/darmoshark-packages/

The signed machine-readable inventory is `channel.json`; `publisher.asc` is the
public key. Pacman repository files are under `arch/x86_64/`. These are artifact
endpoints, not a website requiring an index page. Client trust and source setup
must be explicitly reviewed before normal `pacman -Syu` can use the channel.

## Scope

CachyOS/Arch read-only M3S Pro settings and local profiles. Hardware Apply remains
disabled; this channel adds no device permissions, firmware or setter commands.
No private USB captures, owner artwork, backups or credentials are distributed.
Native Debian/Fedora update support is not established by this pacman repository.

## Verification

Use `tools/verify_channel.py` with an independently checked full fingerprint and
`--directory site` or `--url` plus a new `--output` directory. It changes neither
host trust nor installed packages. Keep the fingerprint independently; trusting
a replacement key downloaded from the same site is insufficient. Standard pacman
signatures do not provide a TUF-style anti-replay guarantee.

Older signed packages are retained for an explicit reviewed rollback; no automatic
downgrade or recovery operation is performed. The manual/push workflow verifies
all staged site content before deploying it through GitHub Pages.
