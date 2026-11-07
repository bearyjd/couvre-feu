#!/bin/sh
# Observation only. Do not source installer code or use this as admission.
# Only metadata and digests leave this process; no raw file/link contents do.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
unset ENV BASH_ENV CDPATH LD_PRELOAD LD_AUDIT
# The vendor stat alternative needs the system library directory.
LD_LIBRARY_PATH=/lib
export LD_LIBRARY_PATH
set -fu

fact() {
    # Per-path field groups mirror the reviewed table. Never emit unreviewed
    # observations just because a required directory unexpectedly became a file.
    case "$1" in
        path:*) case " $probe_fields " in *" ${1##*:} "*) ;; *) return;; esac;;
    esac
    printf 'FACT %s %s\n' "$1" "$2"
}

observe_path() {
    probe_path=$1
    probe_id=path:$probe_path
    case "$probe_path" in
        /proc|/tmp/run/nscd/socket|/run/nscd/socket|/proc/uptime|/proc/self/mountinfo|/proc/sys/kernel/random/boot_id|/etc/config|/etc/crontabs|/etc/couvrefeu|/usr/lib/couvrefeu|/etc/config/firewall|/etc/sysupgrade.conf|/etc/crontabs/root|/etc/firewall.couvrefeu|/usr/sbin/cfctl|/usr/sbin/cfctl-ssh|/usr/sbin/cfctl-scope|/etc/rc.d)
            probe_fields='type';;
        /lib/ld-musl-aarch64.so.1|/bin/stat|/var) probe_fields='type link';;
        /tmp) probe_fields='type metadata';;
        /sbin/logd|/sbin/procd|/etc/init.d/log|/etc/glversion)
            probe_fields='type canonical metadata size sha256';;
        /etc/couvrefeu/platform-profile) probe_fields='type canonical metadata size';;
        /etc/.couvrefeu-mutex) probe_fields='type canonical metadata size links';;
        /etc/passwd|/etc/group|/etc/nsswitch.conf) probe_fields='type canonical metadata size';;
        /lib/libc.so|/lib/libgcc_s.so.1|/usr/libexec/stat-coreutils|/lib/functions.sh|/lib/config/uci.sh|/etc/opkg/keys/06a6bf2ad909388f|/etc/init.d/cron|/etc/rc.common|/lib/functions/procd.sh|/lib/functions/service.sh|/usr/share/libubox/jshn.sh|/etc/init.d/firewall)
            probe_fields='type canonical metadata sha256';;
        *) probe_fields='type canonical metadata';;
    esac
    if [ -L "$probe_path" ]; then probe_type='link'
    elif [ -d "$probe_path" ]; then probe_type=dir
    elif [ -f "$probe_path" ]; then probe_type='file'
    elif [ -e "$probe_path" ]; then probe_type=other
    else probe_type=missing; fi
    fact "$probe_id:type" "$probe_type"
    if [ "$probe_type" = missing ]; then return; fi
    if [ "$probe_fields" = type ]; then return; fi
    probe_meta=$(stat -c '%u:%g:%a' "$probe_path" 2>/dev/null) || probe_meta=UNOBSERVABLE
    case "$probe_meta" in ''|*[!0-9:]*|*:*:*:*) probe_meta=UNOBSERVABLE;; esac
    [ "${#probe_meta}" -le 40 ] || probe_meta=UNOBSERVABLE
    fact "$probe_id:metadata" "$probe_meta"
    probe_parent=${probe_path%/*}
    [ -n "$probe_parent" ] || probe_parent=/
    probe_canonical=$(CDPATH='' cd -P "$probe_parent" 2>/dev/null && pwd -P) || probe_canonical=UNOBSERVABLE
    if [ "$probe_canonical" = "$probe_parent" ]; then probe_canonical=yes
    elif [ "$probe_canonical" != UNOBSERVABLE ]; then probe_canonical=no; fi
    if [ "$probe_type" = dir ] && [ "$probe_canonical" = yes ]; then
        probe_resolved=$(CDPATH='' cd -P "$probe_path" 2>/dev/null && pwd -P) || probe_resolved=UNOBSERVABLE
        if [ "$probe_resolved" = "$probe_path" ]; then :
        elif [ "$probe_resolved" = UNOBSERVABLE ]; then probe_canonical=UNOBSERVABLE
        else probe_canonical=no; fi
    fi
    fact "$probe_id:canonical" "$probe_canonical"
    if [ "$probe_type" = file ]; then
        probe_size=$(stat -c %s "$probe_path" 2>/dev/null) || probe_size=UNOBSERVABLE
        case "$probe_size" in ''|*[!0-9]*) probe_size=UNOBSERVABLE;; esac
        [ "${#probe_size}" -le 10 ] || probe_size=UNOBSERVABLE
        fact "$probe_id:size" "$probe_size"
        probe_hash=UNOBSERVABLE
        if [ "$probe_size" != UNOBSERVABLE ] && [ "$probe_size" -le 16777216 ] && case " $probe_fields " in *' sha256 '*) true;; *) false;; esac; then
            probe_hash=$(sha256sum "$probe_path" 2>/dev/null) || probe_hash=UNOBSERVABLE
            probe_hash=${probe_hash%% *}
            case "$probe_hash" in ''|*[!0-9a-f]*) probe_hash=UNOBSERVABLE;; esac
            [ "${#probe_hash}" = 64 ] || probe_hash=UNOBSERVABLE
        fi
        fact "$probe_id:sha256" "$probe_hash"
        probe_links=$(stat -c %h "$probe_path" 2>/dev/null) || probe_links=UNOBSERVABLE
        case "$probe_links" in ''|*[!0-9]*) probe_links=UNOBSERVABLE;; esac
        [ "${#probe_links}" -le 10 ] || probe_links=UNOBSERVABLE
        fact "$probe_id:links" "$probe_links"
    fi
    case "$probe_path" in
        /lib/ld-musl-aarch64.so.1|/bin/stat|/var)
            probe_link=UNOBSERVABLE
            if [ "$probe_type" = link ]; then
                probe_link=$(readlink "$probe_path" 2>/dev/null) || probe_link=UNOBSERVABLE
                case "$probe_path:$probe_link" in
                    /lib/ld-musl-aarch64.so.1:libc.so|/bin/stat:/usr/libexec/stat-coreutils|/var:tmp) ;;
                    *) [ "$probe_link" = UNOBSERVABLE ] || probe_link=OTHER;;
                esac
            fi
            fact "$probe_id:link" "$probe_link";;
    esac
}

fact probe:format 1
for probe_tool in awk sort stat date sha256sum dd chmod mkdir mktemp mv rm rmdir \
    wc cmp cp tr id dirname env sync cat od sed grep head ls readlink uname \
    timeout busybox flock setsid iptables ip6tables ipset uci ubus jsonfilter conntrack ip fw3
do
    if command -v "$probe_tool" >/dev/null 2>&1; then probe_present=yes; else probe_present=no; fi
    fact "tool:$probe_tool:present" "$probe_present"
done
probe_arch=$(uname -m 2>/dev/null) || probe_arch=UNOBSERVABLE
case "$probe_arch" in aarch64|UNOBSERVABLE) ;; *) probe_arch=OTHER;; esac
fact system:architecture "$probe_arch"
probe_epoch=$(date +%s 2>/dev/null) || probe_epoch=UNOBSERVABLE
case "$probe_epoch" in ''|*[!0-9]*) probe_epoch=UNOBSERVABLE;; esac
[ "${#probe_epoch}" -le 10 ] || probe_epoch=UNOBSERVABLE
fact system:epoch "$probe_epoch"
probe_ticks=$(awk 'NR==1 && NF==2 && $1 ~ /^(0|[1-9][0-9]*)[.][0-9][0-9]$/ && length($1)<=13 {split($1,a,"."); printf "%.0f\n",a[1]*100+a[2]; good=1} END {if(NR!=1||!good)exit 1}' /proc/uptime 2>/dev/null) || probe_ticks=UNOBSERVABLE
fact system:uptime-centiseconds "$probe_ticks"
probe_root=$(awk '/^Uid:|^Gid:/ {if(NF!=5||$3!~/^[0-9]+$/)bad=1; if($3!=0)nonroot=1; count++} END {if(count!=2||bad)exit 1;print(nonroot?"no":"yes")}' /proc/self/status 2>/dev/null) || probe_root=UNOBSERVABLE
fact system:root-credentials "$probe_root"
probe_mounts=UNOBSERVABLE
if [ -r /proc/self/mountinfo ]; then probe_mounts=yes; fi
fact system:mountinfo-readable "$probe_mounts"
probe_mtime=$(stat -c '%Y %y' /etc 2>/dev/null) || probe_mtime=UNOBSERVABLE
if [ "$probe_mtime" != UNOBSERVABLE ]; then
    if printf '%s\n' "$probe_mtime" | awk 'NF==4 && $1 ~ /^-?[0-9]+$/ {n=split($3,t,".");if(n==2&&length(t[2])==9&&t[2]!~/[^0-9]/)good=1} END {exit !good||NR!=1}'; then probe_mtime=yes; else probe_mtime=no; fi
fi
fact system:stat-mtime-format "$probe_mtime"
probe_mount_format=$(stat -c '%d %m' /etc 2>/dev/null) || probe_mount_format=UNOBSERVABLE
if [ "$probe_mount_format" != UNOBSERVABLE ]; then
    if printf '%s\n' "$probe_mount_format" | awk 'NR==1&&NF==2&&$1~/^[0-9]+$/&&$2~/^\// {good=1} END {exit !good||NR!=1}'; then probe_mount_format=yes; else probe_mount_format=no; fi
fi
fact system:stat-mount-format "$probe_mount_format"
probe_boot=UNOBSERVABLE
if [ -r /proc/sys/kernel/random/boot_id ]; then
    probe_boot_body=$(head -c 38 /proc/sys/kernel/random/boot_id 2>/dev/null && printf '.') || probe_boot_body=UNOBSERVABLE
    if [ "$probe_boot_body" != UNOBSERVABLE ]; then
        probe_boot_body=${probe_boot_body%.}
        if [ "${#probe_boot_body}" = 37 ] && printf '%s' "$probe_boot_body" | grep -Eq '^[0-9a-f-]{36}$'; then probe_boot=yes; else probe_boot=no; fi
    fi
fi
fact system:boot-id-shape "$probe_boot"
for probe_entry in \
    / /lib /lib/config /etc /etc/opkg /etc/opkg/keys /usr /usr/bin \
    /usr/lib /usr/libexec /usr/lib/opkg /usr/lib/opkg/info /bin /sbin \
    /usr/sbin /etc/init.d /lib/functions /usr/share /usr/share/libubox /tmp \
    /proc /lib/libc.so /lib/libgcc_s.so.1 /lib/functions.sh /lib/config/uci.sh \
    /etc/opkg/keys/06a6bf2ad909388f /usr/lib/opkg/status /bin/opkg \
    /lib/ld-musl-aarch64.so.1 /usr/libexec/stat-coreutils /bin/stat /sbin/logd \
    /sbin/procd /etc/init.d/log /etc/init.d/cron /etc/rc.common \
    /lib/functions/procd.sh /lib/functions/service.sh /usr/share/libubox/jshn.sh \
    /etc/init.d/firewall /etc/glversion /etc/passwd /etc/group /var /tmp/run \
    /run /tmp/run/nscd /run/nscd /tmp/run/nscd/socket /run/nscd/socket \
    /etc/nsswitch.conf /proc/uptime /proc/self/mountinfo \
    /proc/sys/kernel/random/boot_id /etc/rc.d /etc/crontabs /etc/crontabs/root \
    /etc/config /etc/config/firewall /etc/sysupgrade.conf /etc/firewall.couvrefeu \
    /etc/couvrefeu /usr/lib/couvrefeu /usr/sbin/cfctl /usr/sbin/cfctl-ssh \
    /usr/sbin/cfctl-scope /etc/.couvrefeu-mutex /etc/couvrefeu/platform-profile
do
    observe_path "$probe_entry"
done

# Read-only observations cannot prove these transactional or semantic gates.
for probe_gate in environment root profile-agreement bootstrap-closure release-closure \
    source-syntax helper-ancestry helper-execution helper-sweep session \
    monotonic-deadline census-budget account-semantics account-stability \
    nss-semantics provider-stability supervisor logd-census pins-stability \
    transaction-paths transaction-mutex transaction-owner transaction-fence \
    transaction-entropy platform-lock install-lock core-lock prepared journal \
    retirement release-candidate recovery mount-identity exact-restoration \
    private-runtime dependencies timeout-semantics parser protected-identities \
    ssh-neighbor scope state integration-collisions callback-generation \
    firewall-capabilities firewall-drift cron-enabled cron-running \
    cron-quiescence cleanup-receipt durability temporary-publication \
    external-trust fixture-boundary
do
    fact "runtime:$probe_gate" UNOBSERVABLE
done

