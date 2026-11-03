# Extra binpack packages

`.deb` files from the roothide procursus repo (`https://roothide.github.io/procursus`, suite
`iphoneos-arm64e/1900`, the same repo emexOS's bootstrap uses) for tools the emexOS bootstrap does not
ship. `make recovery-binpack` adds everything they install to `Shared/Recovery/binpack.zip` and prints a
warning for every library still missing: fetch that package too and rebuild.

Bundled: `nano` (TWRP's file manager "Edit File"), `curl`, `wget` and the archivers (`zip`, `unzip`,
`gzip`, `bzip2`, `xz`, `zstd`, `lz4`, `7z`, `cpio`, `unrar`, `bsdtar`/`bsdcpio`/`bsdcat`, `brotli`,
`xar`), with the dependencies the bootstrap lacks. `PACKAGES` lists them with their SHA256 and pool
path from the repo's `Packages` index; `*.deb` is git-ignored, so `./fetch.sh` downloads and verifies
them again.
