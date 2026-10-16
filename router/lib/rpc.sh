# shellcheck shell=sh
# shellcheck disable=SC2034,SC2015
# RPC identity is accepted-policy evidence; runtime status remains independent.
cf_rpc_checkpoint() {
    # Fixture-only process interruption; never enabled by production environment.
    if [ "$CF_LOCAL_TEST" = 1 ] && [ "${CF_TEST_RPC_STOP:-}" = "$1" ];then
        printf '%s\n' "$1" > "$CF_BASE/rpc-stopped"
        kill -STOP "$$"
    fi
}
cf_operation_valid() { case $1 in ''|-|*[!a-z0-9_-]*)return 1;;esac;[ "${#1}" -le 64 ]; }
cf_rpc_binding() {
    CF_SCOPE=
    if [ -z "$CF_METADATA" ];then
        # Missing state metadata cannot silently downgrade a recorded scope.
        for cf_scope_journal in "$CF_DIR/backup/etc_couvrefeu_rpc-allowed.after" "$CF_DIR/backup/etc_couvrefeu_rpc-allowed.staged";do
            [ ! -e "$cf_scope_journal" ] && [ ! -L "$cf_scope_journal" ] || { cf_fail invalid_rpc_scope;return 1; }
        done
        [ ! -e "$CF_DIR/rpc-allowed" ] && [ ! -L "$CF_DIR/rpc-allowed" ] || { cf_fail invalid_rpc_scope;return 1; }
        return 0
    fi
    cf_private_dir "$CF_DIR/backup" && cf_safe_file "$CF_DIR/backup/ready" || { cf_fail inactive_generation;return 1; }
    [ "$(wc -c < "$CF_DIR/backup/ready")" = 2 ] && [ "$(cat "$CF_DIR/backup/ready")" = 1 ] || { cf_fail inactive_generation;return 1; }
    if [ "${CF_INSTALL_AUTH:-0}" != 1 ];then
        cf_safe_file "$CF_DIR/backup/complete" && [ "$(wc -c < "$CF_DIR/backup/complete")" = 2 ] && [ "$(cat "$CF_DIR/backup/complete")" = 1 ] || { cf_fail inactive_generation;return 1; }
    fi
    cf_safe_file "$CF_DIR/rpc-allowed" && cf_safe_file "$CF_DIR/backup/etc_couvrefeu_rpc-allowed.staged" && cf_safe_file "$CF_DIR/backup/etc_couvrefeu_state.staged" || { cf_fail invalid_rpc_scope;return 1; }
    cmp -s "$CF_DIR/rpc-allowed" "$CF_DIR/backup/etc_couvrefeu_rpc-allowed.staged" || { cf_fail invalid_rpc_scope;return 1; }
    CF_SCOPE=$(awk 'NR==1{print}END{if(NR!=1)exit 2}' "$CF_DIR/rpc-allowed") || { cf_fail invalid_rpc_scope;return 1; }
    cf_mac_valid "$CF_SCOPE" && [ "$(wc -c < "$CF_DIR/rpc-allowed")" = 18 ] || { cf_fail invalid_rpc_scope;return 1; }
    [ "$(wc -c < "$CF_DIR/backup/etc_couvrefeu_state.staged")" -le 131072 ] || { cf_fail inactive_generation;return 1; }
    cf_binding_meta=$(awk -v mode=meta -f "$CF_LIB/state.awk" "$CF_DIR/backup/etc_couvrefeu_state.staged") || { cf_fail inactive_generation;return 1; }
    [ "$(printf '%s\n' "$cf_binding_meta" | awk -F '\t' '$1=="G"{print $2}')" = "$CF_GENERATION" ] || { cf_fail inactive_generation;return 1; }
    # Bind both immutable staged files to their installer signatures.
    for cf_binding_key in etc_couvrefeu_state etc_couvrefeu_rpc-allowed;do
        cf_safe_file "$CF_DIR/backup/$cf_binding_key.after" || { cf_fail inactive_generation;return 1; }
        [ "$(wc -c < "$CF_DIR/backup/$cf_binding_key.after")" -le 512 ] || { cf_fail inactive_generation;return 1; }
        cf_binding_sig=$(printf '%s:%s\n' "$(sha256sum "$CF_DIR/backup/$cf_binding_key.staged" | awk '{print $1}')" "$(stat -c '%a:%u:%g' "$CF_DIR/backup/$cf_binding_key.staged")")
        [ "$(cat "$CF_DIR/backup/$cf_binding_key.after")" = "$cf_binding_sig" ] || { cf_fail inactive_generation;return 1; }
    done
}
cf_scope_safe() {
    [ -n "$CF_SCOPE" ] || return 0
    printf '%s\n' "$CF_POLICY" | awk -F '\t' -v mac="$CF_SCOPE" '$1=="P"&&$3!="-"&&$3!=mac{exit 1}' || { cf_fail rpc_scope_overlap;return 1; }
    awk -v mac="$CF_SCOPE" '$0==mac{exit 1}' "$CF_PROTECTED" || { cf_fail protected_mac_overlap;return 1; }
}
cf_receipt_json() {
    cf_receipt_id=$1
    [ -n "$cf_receipt_id" ] && [ "$cf_receipt_id" != - ] || { printf 'null';return 0; }
    printf '%s\n' "$CF_METADATA" | awk -F '\t' -v id="$cf_receipt_id" -v current="$CF_CURRENT" '$1=="O"&&$2==id{printf "{\"operationId\":\"%s\",\"requestDigest\":\"%s\",\"baseRevision\":%s,\"baseDigest\":\"%s\",\"acceptedRevision\":%s,\"acceptedDigest\":\"%s\",\"outcome\":\"accepted\",\"current\":%s}",$2,$3,$4,$5,$6,$7,($2==current?"true":"false");found=1}END{if(!found)printf "null"}'
}
cf_rpc_response() {
    cf_rpc_error=$CF_ERROR
    cf_state_load || { cf_rpc_reject;return 1; }
    # Subshell observation avoids modifying the locked accepted authority globals.
    cf_rpc_status=$(cf_status)
    cf_rpc_status_rc=$?
    cf_rpc_policy=$(printf '%s\n' "$CF_POLICY" | cf_state_json -) || cf_rpc_policy=null
    cf_rpc_errors='[]'
    [ -z "$cf_rpc_error" ] || cf_rpc_errors=$(printf '%s\n' "$cf_rpc_error" | cf_json_strings)
    cf_rpc_current=null
    [ -z "$CF_CURRENT" ] || [ "$CF_CURRENT" = - ] || cf_rpc_current="\"$CF_CURRENT\""
    cf_rpc_generation=null
    [ -z "$CF_GENERATION" ] || cf_rpc_generation="\"$CF_GENERATION\""
    cf_rpc_checkpoint before_reply
    cf_rpc_output=$(printf '{"rpc_version":1,"generation":%s,"acceptedPolicy":%s,"policyDigest":"%s","currentOperationId":%s,"routerTime":%s,"receipt":%s,"status":%s,"errors":%s}' "$cf_rpc_generation" "$cf_rpc_policy" "$CF_DIGEST" "$cf_rpc_current" "${CF_NOW_VALUE:-0}" "$(cf_receipt_json "${CF_RESPONSE_ID:-$CF_CURRENT}")" "$cf_rpc_status" "$cf_rpc_errors")
    [ "${#cf_rpc_output}" -lt 131072 ] || { printf '%s\n' '{"rpc_version":1,"errors":["response_too_large"]}';return 1; }
    printf '%s\n' "$cf_rpc_output"
    [ -z "$cf_rpc_error" ]
}
cf_rpc_reject() {
    # Busy/invalid authority cannot return an authoritative accepted witness.
    printf '{"rpc_version":1,"errors":["%s"]}\n' "${CF_ERROR:-invalid_command}"
    return 1
}
cf_rpc_main() {
    CF_RESPONSE_ID=
    CF_METADATA=;CF_GENERATION=;CF_CURRENT=;CF_POLICY=;CF_DIGEST=
    cf_action=$1
    if [ "$cf_action" = rpc-sync ];then
        [ "$#" = 1 ] || { cf_fail invalid_command;cf_rpc_reject;return 2; }
    else
        [ "$#" = 2 ] || [ "$#" = 3 ] || { cf_fail invalid_command;cf_rpc_reject;return 2; }
        [ "$2" = --json ] || { cf_fail invalid_command;cf_rpc_reject;return 2; }
        if [ "$#" = 3 ];then cf_operation_valid "$3" || { cf_fail invalid_command;cf_rpc_reject;return 2; };CF_RESPONSE_ID=$3;fi
    fi
    cf_install_gate "$cf_action" || { cf_rpc_reject;return 1; }
    if [ "$cf_action" = rpc-sync ];then cf_sync_stage 1 || { cf_rpc_reject;return 1; };fi
    # RPC never recreates runtime paths after teardown; scoped activation owns them.
    cf_control_dirs && cf_state_load || { cf_rpc_reject;return 1; }
    [ -n "$CF_GENERATION" ] || { cf_fail rpc_disabled;cf_rpc_reject;return 1; }
    CF_RPC_REQUIRE_RUNTIME=1
    cf_rpc_checkpoint before_lock
    cf_lock || { cf_rpc_reject;return 1; }
    cf_install_gate "$cf_action" && cf_control_dirs && cf_state_load && cf_clock && cf_protected_valid && cf_policy_safe || { cf_rpc_reject;return 1; }
    [ -n "$CF_GENERATION" ] || { cf_fail rpc_disabled;cf_rpc_reject;return 1; }
    if [ "$cf_action" = rpc-status ];then cf_rpc_response;return $?;fi
    [ "$CF_REQUEST_GENERATION" = "$CF_GENERATION" ] || { cf_fail generation_conflict;cf_rpc_response;return 1; }
    CF_RESPONSE_ID=$CF_REQUEST_ID
    cf_request_digest=$(printf 'rpc1\n%s\n%s\n%s\n%s\n%s\n' "$CF_REQUEST_GENERATION" "$CF_REQUEST_ID" "$CF_BASE_REVISION" "$CF_BASE_DIGEST" "$CF_NEXT_DIGEST" | sha256sum | awk '{print $1}')
    cf_prior_request=$(printf '%s\n' "$CF_METADATA" | awk -F '\t' -v id="$CF_REQUEST_ID" '$1=="O"&&$2==id{print $3}')
    if [ -n "$cf_prior_request" ];then
        [ "$cf_prior_request" = "$cf_request_digest" ] || { cf_fail operation_conflict;cf_rpc_response;return 1; }
        cf_rpc_response;return $?
    fi
    [ "$CF_BASE_REVISION" = "$CF_REVISION" ] && [ "$CF_BASE_DIGEST" = "$CF_DIGEST" ] || { cf_fail policy_conflict;cf_rpc_response;return 1; }
    [ "$(printf '%s\n' "$CF_METADATA" | awk -F '\t' '$1=="O"{n++}END{print n+0}')" -lt 128 ] || { cf_fail receipt_capacity;cf_rpc_response;return 1; }
    cf_backend_available sync || { cf_fail missing_dependencies;cf_rpc_response;return 1; }
    CF_OLD_POLICY=$CF_POLICY
    CF_OLD_DIGEST=$CF_DIGEST
    CF_POLICY=$CF_STAGED_POLICY
    cf_policy_safe && cf_ssh_guard && cf_preflight || { cf_rpc_response;return 1; }
    platform_deadline_check
    cf_transition_prepare || { cf_error_record;cf_rpc_response;return 1; }
    CF_REVISION=$((CF_BASE_REVISION + 1));CF_DIGEST=$CF_NEXT_DIGEST;CF_CURRENT=$CF_REQUEST_ID
    CF_METADATA=$(printf '%s\n' "$CF_METADATA" | awk -F '\t' -v id="$CF_CURRENT" 'BEGIN{OFS="\t"}$1=="C"{$2=id}{print}')
    CF_METADATA="$CF_METADATA
$(printf 'O\t%s\t%s\t%s\t%s\t%s\t%s' "$CF_REQUEST_ID" "$cf_request_digest" "$CF_BASE_REVISION" "$CF_BASE_DIGEST" "$CF_REVISION" "$CF_DIGEST")"
    cf_write_policy || { cf_error_record;cf_rpc_reject;return 1; }
    if ! cf_apply;then CF_ERROR=${CF_ERROR:-apply_failed};cf_error_record;fi
    cf_rpc_checkpoint after_apply
    cf_rpc_response
}
