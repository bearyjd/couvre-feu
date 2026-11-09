#!/bin/sh
# /usr/local/sbin/couvrefeu-heartbeat (0700 root). Run every minute by couvrefeu-heartbeat.timer.
# Reports status=up only if both units are enabled at boot, the app is active, the agent holds a key and
# (when HEARTBEAT_HEALTH_URL is set) GET /health answers 200 with ok:true. Otherwise status=down with a fixed msg.
# HEARTBEAT_URL_FILE holds ONLY the bare monitor push URL (no query string); it is a credential: root-owned, 0600,
# not a symlink. Both URLs must be https unless HEARTBEAT_ALLOW_HTTP=1 (plain http is acceptable on a LAN for the
# content-free /health; do not use it for the push URL across the internet).
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
set -u
umask 077
URL_FILE=${HEARTBEAT_URL_FILE:-/root/couvrefeu-key/heartbeat-push-url}
SSH_AUTH_SOCK=${HEARTBEAT_AGENT_SOCK:-/run/couvrefeu/agent.sock}
export SSH_AUTH_SOCK
if [ "${HEARTBEAT_ALLOW_HTTP:-}" = 1 ]; then PROTO=http,https; else PROTO=https; fi

# A URL goes into a curl config line as root, so only a strict character set (no quote, space, newline, backslash)
# and an allowed scheme are accepted. Anything else is refused before curl sees it.
valid_url() {
    case $1 in
        ''|*[!A-Za-z0-9._~:/@+%-]*) return 1;;
        https://?*) return 0;;
        http://?*) [ "$PROTO" = http,https ];;
        *) return 1;;
    esac
}

# msg is always one of these fixed [A-Za-z0-9_.-] tokens, so nothing can break out of the curl config line.
if ! systemctl is-enabled --quiet couvrefeu || ! systemctl is-enabled --quiet couvrefeu-agent; then
    status=down; msg=service-disabled
elif ! systemctl is-active --quiet couvrefeu; then
    status=down; msg=service-down
elif ! timeout 10 ssh-add -l >/dev/null 2>&1; then
    status=down; msg=agent-empty
else
    status=up; msg=ok
    if [ -n "${HEARTBEAT_HEALTH_URL:-}" ]; then
        # Content-free GET: only the status code and the ok flag are looked at. The URL goes to curl on stdin too.
        reply=
        if valid_url "$HEARTBEAT_HEALTH_URL"; then
            reply=$(printf 'url = "%s"\n' "$HEARTBEAT_HEALTH_URL" |
                curl -q -sS -m 10 --max-filesize 65536 --proto "=$PROTO" --proto-redir "=$PROTO" -K - -w '\n%{http_code}' 2>/dev/null) || reply=
        fi
        code=${reply##*
}
        if [ "$code" != 200 ] || ! printf '%s\n' "$reply" | grep -Eq '"ok"[[:space:]]*:[[:space:]]*true'; then
            status=down; msg=health-failed
        fi
    fi
fi
printf 'couvrefeu-heartbeat: status=%s msg=%s\n' "$status" "$msg"

if [ -L "$URL_FILE" ] || [ ! -f "$URL_FILE" ] || [ ! -r "$URL_FILE" ]; then
    printf 'couvrefeu-heartbeat: push URL file missing, unreadable or a symlink; not pushing\n' >&2
    exit 1
fi
if [ "$(stat -c %u:%a "$URL_FILE" 2>/dev/null)" != 0:600 ]; then
    printf 'couvrefeu-heartbeat: push URL file must be owned by root with mode 0600; not pushing\n' >&2
    exit 1
fi
URL=$(cat "$URL_FILE")
if ! valid_url "$URL"; then
    printf 'couvrefeu-heartbeat: push URL file empty, not https (or http without HEARTBEAT_ALLOW_HTTP=1) or has unexpected characters; not pushing\n' >&2
    exit 1
fi
# The URL is a credential: it goes to curl on stdin (-K -), never in argv where ps and /proc/<pid>/cmdline show it.
rc=0
printf 'url = "%s?status=%s&msg=%s"\n' "$URL" "$status" "$msg" | curl -q -fsS -m 10 --proto "=$PROTO" --proto-redir "=$PROTO" -K - >/dev/null 2>&1 || rc=$?
if [ "$rc" != 0 ]; then
    printf 'couvrefeu-heartbeat: push failed rc=%s\n' "$rc" >&2
    exit 1
fi
