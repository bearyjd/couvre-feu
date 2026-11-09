#!/bin/sh
# /usr/local/sbin/couvrefeu-heartbeat (0700 root). Run every minute by couvrefeu-heartbeat.timer.
# Reports status=up only if both units are enabled at boot, the app is active, the agent holds a key and
# (when HEARTBEAT_HEALTH_URL is set) GET /health answers 200 with ok:true. Otherwise status=down with a fixed msg.
# HEARTBEAT_URL_FILE holds ONLY the bare monitor push URL (no query string); it is a credential, root-only.
set -u
umask 077
URL_FILE=${HEARTBEAT_URL_FILE:-/root/couvrefeu-key/heartbeat-push-url}
SSH_AUTH_SOCK=${HEARTBEAT_AGENT_SOCK:-/run/couvrefeu/agent.sock}
export SSH_AUTH_SOCK

# msg is always one of these fixed [A-Za-z0-9_.-] tokens, so nothing can break out of the curl config line.
if ! systemctl is-enabled --quiet couvrefeu || ! systemctl is-enabled --quiet couvrefeu-agent; then
    status=down; msg=service-disabled
elif ! systemctl is-active --quiet couvrefeu; then
    status=down; msg=service-down
elif ! ssh-add -l >/dev/null 2>&1; then
    status=down; msg=agent-empty
else
    status=up; msg=ok
    if [ -n "${HEARTBEAT_HEALTH_URL:-}" ]; then
        # Content-free GET: only the status code and the ok flag are looked at. The URL goes to curl on stdin too.
        reply=$(printf 'url = "%s"\n' "$HEARTBEAT_HEALTH_URL" | curl -sS -m 10 -K - -w '\n%{http_code}' 2>/dev/null) || reply=
        code=${reply##*
}
        if [ "$code" != 200 ] || ! printf '%s\n' "$reply" | grep -Eq '"ok"[[:space:]]*:[[:space:]]*true'; then
            status=down; msg=health-failed
        fi
    fi
fi
printf 'couvrefeu-heartbeat: status=%s msg=%s\n' "$status" "$msg"

if [ ! -r "$URL_FILE" ]; then
    printf 'couvrefeu-heartbeat: push URL file missing or unreadable; not pushing\n' >&2
    exit 1
fi
URL=$(cat "$URL_FILE")
case $URL in
    ''|*[!A-Za-z0-9._~:/@+%-]*)
        printf 'couvrefeu-heartbeat: push URL file empty or has unexpected characters; not pushing\n' >&2
        exit 1;;
esac
# The URL is a credential: it goes to curl on stdin (-K -), never in argv where ps and /proc/<pid>/cmdline show it.
if ! printf 'url = "%s?status=%s&msg=%s"\n' "$URL" "$status" "$msg" | curl -fsS -m 10 -K - >/dev/null 2>&1; then
    printf 'couvrefeu-heartbeat: push failed\n' >&2
    exit 1
fi
