"""Measured overlayfs identity model for installer fixtures (no index, no xino).

GL-XE3000, OpenWrt 21.02, read-only probe 2026-10-14: `/` is
`overlay lowerdir=/,upperdir=/overlay/upper` over squashfs `/rom` and f2fs
`/overlay`, overlay dev 19.

- copied up with an origin xattr: `stat -c %d:%i` reports the overlay dev and
  the *lower* inode (`/etc/sysupgrade.conf` 19:1072, `/rom/...` 45831:1072);
- pure upper (e.g. replaced by rename, no origin): the upper file's real
  dev:ino (`/etc/config/firewall` 66304:1409);
- a new hard link to a copied-up file with an origin reports a different
  dev:ino than the original name (live refusal at install.sh:296). Without
  index=on, overlayfs documents such hard links as broken.

Model, applied by a `stat` shim to every `%d`/`%i` query:
- `lower` (never copied up) and `origin` (copied up with an origin): while
  the real file has one link, every name reports OVERLAY_DEV:<lower inode>.
  With more links the original (cached) name keeps that identity and any
  other name reports the real dev:ino. Only "differs" is measured; the
  link's exact value is not.
- `upper`: real dev:ino, unchanged.
- `absent`: no file.
A `lower` file is additionally copied up by any metadata, link or rename
operation; `ln`, `chmod`, `chown`, `touch` and `mv` (source operands only)
shims log such an operation on a `lower` managed path as `copy-up <path> <tool>`
(a write to a managed path).

Directories (`stat -c '%d %m'`, the installer's same-filesystem proof) report
the overlay dev and mount point `/` of the merged root. `mounts` may split a
subtree onto another filesystem; only directories are modeled, and the query
is logged as `mount <path> <dev> <mount point>`.
"""
import os
from pathlib import Path
import shlex
import shutil

OVERLAY_DEV = 19
STATES = ('lower', 'origin', 'upper', 'absent')


def install(bin_dir, log, entries, root, mounts=None):
    """Front `stat`, `ln`, `chmod`, `chown`, `touch`, `mv` in bin_dir with the model.

    entries: {absolute path: (state, lower inode)} for existing originals.
    root: the merged overlay root; mounts: {absolute subtree: (dev, mount point)}.
    """
    bin_dir = Path(bin_dir)
    table = bin_dir / 'overlay.table'
    lines = []
    for path, (state, lower_ino) in entries.items():
        if state not in STATES:
            raise ValueError(state)
        if state in ('lower', 'origin'):
            st = os.lstat(path)
            lines.append(f'{st.st_dev}:{st.st_ino} {path} {lower_ino} {state}\n')
    table.write_text(''.join(lines))
    mount_table = bin_dir / 'overlay.mounts'
    splits = dict(mounts or {})
    mount_table.write_text(''.join(f'{prefix} {dev} {point}\n' for prefix, (dev, point) in
                                   [(str(root), (OVERLAY_DEV, '/')), *splits.items()]))
    real_stat = shutil.which('stat')
    q = shlex.quote
    stat_shim = f'''#!/bin/sh
# Overlay identity shim; every other stat format runs the real tool.
case "${{1:-}}:${{2:-}}" in -c:*%d*|-c:*%i*|-c:*%m*) ;; *) exec {q(real_stat)} "$@";; esac
fmt=$2
shift 2
if [ "$fmt" = '%d %m' ]; then
    status=0
    for path do
        [ -d "$path" ] && [ ! -L "$path" ] || {{ printf 'overlay stat: only directories are modeled: %s\\n' "$path" >&2; exit 97; }}
        reported=$(awk -v path="$path" '(path==$1 || index(path, $1 "/")==1) && length($1)>=best {{best=length($1); r=$2 " " $3}} END {{if(r=="") exit 1; print r}}' {q(str(mount_table))}) || {{ status=1; continue; }}
        printf 'mount %s %s\\n' "$path" "$reported" >> {q(str(log))}
        printf '%s\\n' "$reported"
    done
    exit $status
fi
case "$fmt" in '%d:%i'|'%i'|'%d') ;; *) printf 'overlay stat: unmodeled format %s\\n' "$fmt" >&2; exit 97;; esac
status=0
for path do
    real=$({q(real_stat)} -c '%d:%i %h' "$path") || {{ status=1; continue; }}
    links=${{real##* }} id=${{real% *}}
    reported=$(awk -v id="$id" -v path="$path" -v links="$links" '$1==id && (links==1 || $2==path) {{print "{OVERLAY_DEV}:" $3; exit}}' {q(str(table))})
    [ -n "$reported" ] || reported=$id
    printf 'stat %s %s\\n' "$path" "$reported" >> {q(str(log))}
    case "$fmt" in '%d:%i') printf '%s\\n' "$reported";; '%i') printf '%s\\n' "${{reported#*:}}";; '%d') printf '%s\\n' "${{reported%%:*}}";; esac
done
exit $status
'''
    (bin_dir / 'stat').write_text(stat_shim)
    (bin_dir / 'stat').chmod(0o700)
    for tool in ('ln', 'chmod', 'chown', 'touch', 'mv'):
        target = bin_dir / tool
        # Wrap an existing fixture wrapper (e.g. a truncating touch) if present.
        real = str(target.with_name(tool + '.overlay-real')) if target.exists() else shutil.which(tool)
        if target.exists():
            target.rename(real)
        target.write_text(f'''#!/bin/sh
# A metadata or link operation on a lower-only file copies it up first.
skip=0 left=$#
for operand do
    left=$((left - 1))
    # touch -r only reads its reference file; mv renames (copies up) its sources only.
    if [ "$skip" = 1 ]; then skip=0; continue; fi
    case "$operand" in -r) skip=1; continue;; -*) continue;; esac
    if [ {tool} = mv ] && [ "$left" = 0 ]; then continue; fi
    if awk -v p="$operand" '$2==p && $4=="lower" {{found=1}} END {{exit !found}}' {q(str(table))}; then
        printf 'copy-up %s {tool}\\n' "$operand" >> {q(str(log))}
    fi
done
exec {q(real)} "$@"
''')
        target.chmod(0o700)
