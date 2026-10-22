#!/bin/sh
# Defaults to read-only discovery. No SSH, router mutation or network probes.
set -eu

case "${1:---preflight}" in
    --preflight)
        [ "$#" -le 1 ] || exit 2
        printf '%s\n' 'Couvre-feu acceptance: read-only local preflight'
        for tool in busybox shellcheck awk timeout iptables ip6tables ipset conntrack fw3 uci; do
            if command -v "$tool" >/dev/null 2>&1; then
                printf 'AVAILABLE: %s\n' "$tool"
            else
                printf 'PENDING prerequisite: %s\n' "$tool"
            fi
        done
        printf '%s\n' 'Parser: bundled strict POSIX AWK; jsonfilter is not a dependency.'
        printf '%s\n' \
            'PENDING: real isolated OpenWrt/fw3 established-session and schedule tests.' \
            'PENDING: separately approved live test MAC, exact commands and rollback.' \
            'PENDING: 5-second cutoff, adult access/DNS, GL DNS marks, IPv6 and acceleration.' \
            'PENDING: service-off expiry, reload/reboot, Dropbear restriction, firmware upgrade.' \
            'Mock results cannot satisfy these acceptance gates.'
        ;;
    --fixtures)
        [ "$#" -eq 1 ] || exit 2
        printf '%s\n' \
            'PRP §8 fixture coverage (command/state doubles, no packet proof):' \
            '1: multi-device pause/resume, protected adults, connection-eviction argv.' \
            '2: local expiry with no service and replay/backward-clock protection.' \
            '3: native metadata/early schedule mirrors and cross-midnight windows.' \
            '4: reconstruction after simulated reload, repeat apply, interrupted apply.' \
            '5–7: scoped DNS and dual-family rules; actual traffic remains pending.' \
            '8: strict forced-command grammar and environment confinement fixtures.' \
            '9: exact recovery/preservation fixtures; actual firmware upgrade pending.'
        REPO=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
        exec sh "$REPO/tests/run.sh"
        ;;
    --installed)
        [ "$#" -eq 1 ] || exit 2
        [ "$(id -u)" = 0 ] || { printf '%s\n' 'REFUSED: installed inspection requires router root.' >&2; exit 2; }
        [ -z "${CF_TEST_MODE-}${CF_ROOT-}${CF_BACKEND_DIR-}" ] || {
            printf '%s\n' 'REFUSED: installed inspection rejects fixture overrides.' >&2; exit 2;
        }
        PATH=/usr/sbin:/usr/bin:/sbin:/bin
        export PATH
        if [ ! -x /usr/sbin/cfctl ] || [ -L /usr/sbin/cfctl ]; then exit 1; fi
        printf '%s\n' 'Read-only installed checks: no expiry, apply, reload or packet probes.'
        /usr/sbin/cfctl check
        STATUS=$(/usr/sbin/cfctl status --json)
        printf '%s\n' "$STATUS"
        case "$STATUS" in '{"ok":true,'*) ;; *) printf '%s\n' 'FAIL: observed state is uncertain or differs.' >&2; exit 1;; esac
        [ "$(uci -q get firewall.couvrefeu.type)" = script ]
        [ "$(uci -q get firewall.couvrefeu.path)" = /etc/firewall.couvrefeu ]
        [ "$(uci -q get firewall.couvrefeu.reload)" = 1 ]
        [ -f /etc/firewall.couvrefeu ] && [ ! -L /etc/firewall.couvrefeu ]
        awk '$0=="exec /usr/sbin/cfctl apply-fw"{n++}END{exit n!=1}' /etc/firewall.couvrefeu
        awk '$0=="* * * * * /usr/sbin/cfctl expire"{n++}END{exit n!=1}' /etc/crontabs/root
        for PRESERVED in /etc/couvrefeu /usr/sbin/cfctl /usr/sbin/cfctl-ssh /usr/sbin/cfctl-scope /etc/firewall.couvrefeu /usr/lib/couvrefeu; do
            awk -v path="$PRESERVED" '$0==path{found=1}END{exit !found}' /etc/sysupgrade.conf || {
                printf 'FAIL: missing preservation entry: %s\n' "$PRESERVED" >&2; exit 1;
            }
        done
        for PRIVATE in /etc/couvrefeu/state /etc/couvrefeu/protected; do
            if [ ! -f "$PRIVATE" ] || [ -L "$PRIVATE" ] || [ "$(stat -c '%a:%u' "$PRIVATE")" != 600:0 ]; then exit 1; fi
        done
        printf '%s\n' 'PASS: current installed structure and observed state; packet/reboot/key/upgrade gates pending.'
        ;;
    --live)
        [ "$#" -eq 1 ] || exit 2
        [ "${CF_ACCEPT_LIVE:-0}" = 1 ] || {
            printf '%s\n' 'REFUSED: explicit CF_ACCEPT_LIVE=1 and supplied TEST_MAC are required.' >&2
            exit 2
        }
        if [ -z "${PROTECTED_MAC_FILE:-}" ] || [ ! -f "$PROTECTED_MAC_FILE" ] || [ -L "$PROTECTED_MAC_FILE" ]; then
            printf '%s\n' 'REFUSED: supply a readable, nonsymlink PROTECTED_MAC_FILE.' >&2; exit 2;
        fi
        awk -v target="${TEST_MAC:-}" '
        function valid(mac,a,n,i){n=split(mac,a,":");if(n!=6||length(mac)!=17||mac=="00:00:00:00:00:00")return 0;for(i=1;i<=6;i++)if(a[i]!~/^[0-9a-f][0-9a-f]$/)return 0;return index("02468ace",substr(a[1],2,1))>0}
        BEGIN{if(!valid(target))exit 2}
        {if(!valid($0)||seen[$0]++||$0==target)bad=1;count++}
        END{if(bad||!count)exit 2}' "$PROTECTED_MAC_FILE" || {
            printf '%s\n' 'REFUSED: invalid test/protected MAC or protected overlap.' >&2; exit 2;
        }
        printf '%s\n' \
            'PENDING: environment variables express test scope, not authorization.' \
            'No live actions are implemented here. Review and explicitly approve an exact' \
            'test script, target router, protected identities and rollback before execution.' >&2
        exit 3
        ;;
    *)
        printf '%s\n' 'Usage: tests/acceptance.sh [--preflight|--fixtures|--installed|--live]' >&2
        exit 2
        ;;
esac
