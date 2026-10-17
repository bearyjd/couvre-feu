# shellcheck shell=sh
# shellcheck disable=SC2034,SC2015,SC2086
# Cross-module globals; A && B || fail intentionally rejects either failure.
# Read-only, privacy-scoped per-child network counters. Pure counter rules in an
# owned mangle chain; they carry no target and can never change a verdict.
CF_ACCT_CHAIN=cf_acct
CF_ACCT_HOOK='-m comment --comment cfa/hook'
CF_ACCT_MAX_DEVICES=256
CF_ACCT_EPOCH_FILE=activity.epoch

# Persisted monotonic generation: the last counter_epoch ever stamped.
cf_acct_epoch_read() {
    cf_er_path=$CF_RUNTIME/$CF_ACCT_EPOCH_FILE
    if [ ! -e "$cf_er_path" ] && [ ! -L "$cf_er_path" ];then printf '%s\n' 0;return 0;fi
    cf_safe_file "$cf_er_path" || { cf_fail unsafe_activity_epoch;return 1; }
    awk 'NR==1&&$0~/^[1-9][0-9]*$/&&length($0)<=15{v=$0}END{if(NR!=1||v=="")exit 2;print v}' "$cf_er_path" || { cf_fail unsafe_activity_epoch;return 1; }
}

# person<TAB>mac for MACs assigned to a person, never protected/management MACs.
cf_acct_devices() {
    printf '%s\n' "$CF_POLICY" | awk -F '\t' -v scope="${CF_SCOPE-}" 'BEGIN{n=split(scope,s," ");for(i=1;i<=n;i++)allowed[s[i]]=1}NR==FNR{if(NF)protected[$1]=1;next}$1=="P"&&$3!="-"&&!protected[$3]&&(scope==""||($3 in allowed)){print $2 "\t" $3}' "$CF_PROTECTED" - | sort -u
}
# Fresh unique ip<TAB>mac pairs for enrolled MACs only (same attribution as enforcement).
cf_acct_pairs() {
    cf_acct_pair_data=$(cf_addresses) || return 1
    printf '%s\n' "$cf_acct_pair_data" | awk -F '\t' -v macs="$1" 'BEGIN{n=split(macs,a,"\n");for(i=1;i<=n;i++)if(a[i]!="")m[a[i]]=1}NF==2&&m[$2]{print $1 "\t" $2}' | sort -t . -k1,1n -k2,2n -k3,3n -k4,4n
}
# family<TAB>rule arguments: outbound by source MAC (both families), inbound by IPv4 destination.
cf_acct_plan() {
    cf_ap_devices=$(cf_acct_devices) || return 1
    cf_ap_macs=$(printf '%s\n' "$cf_ap_devices" | awk -F '\t' 'NF==2{print $2}')
    cf_ap_pairs=$(cf_acct_pairs "$cf_ap_macs") || return 1
    printf '%s\n' "$cf_ap_devices" | awk -F '\t' -v pairs="$cf_ap_pairs" '
    BEGIN{n=split(pairs,a,"\n");for(i=1;i<=n;i++){split(a[i],b,"\t");if(b[1]!=""&&index(b[1],":")==0)ip[b[2]]=ip[b[2]] " " b[1]}}
    NF==2{
        for(f=4;f<=6;f+=2)printf "%s\t-i br-lan -m mac --mac-source %s -m comment --comment cfa/tx/%s\n",f,$2,$2
        k=split(ip[$2],c," ");for(i=1;i<=k;i++)if(c[i]!="")printf "4\t-o br-lan -d %s -m comment --comment cfa/rx/%s/%s\n",c[i],$2,c[i]
    }'
}
cf_acct_normal() { awk '{gsub(/"/,"")}{print}' | cf_normal_rules; }
cf_acct_body() {
    cf_ab_raw=$(cf_table "$1" -t mangle -S "$CF_ACCT_CHAIN" 2>/dev/null) || return 1
    printf '%s\n' "$cf_ab_raw" | cf_acct_normal | awk '$1=="-A"'
}
cf_acct_stamp() {
    # Prints "<epoch> <slot>" from a valid first stamp rule.
    printf '%s\n' "$1" | awk 'NR==1{for(i=1;i<NF;i++)if($i=="--comment"){n=split($(i+1),a,"/");if(n==4&&a[1]=="cfa"&&a[2]=="epoch"&&a[3]~/^[1-9][0-9]*$/&&length(a[3])<=10&&a[4]~/^[ab]$/&&NF==6)print a[3] " " a[4]}}'
}
cf_acct_hook_ok() {
    cf_ah_raw=$(cf_table "$1" -t mangle -S FORWARD 2>/dev/null) || return 1
    cf_ah_lines=$(printf '%s\n' "$cf_ah_raw" | cf_acct_normal | awk '$1=="-A"')
    cf_ah_exact=$(printf '%s\n' "-A FORWARD $CF_ACCT_HOOK -j $CF_ACCT_CHAIN" | cf_normal_rules)
    [ "$(printf '%s\n' "$cf_ah_lines" | awk 'NR==1{print}')" = "$cf_ah_exact" ] || return 1
    printf '%s\n' "$cf_ah_lines" | awk -v c="$CF_ACCT_CHAIN" '{for(i=1;i<NF;i++)if(($i=="-j"||$i=="-g")&&$(i+1)==c)n++}END{exit n!=1}'
}
cf_acct_unhook() {
    # Delete only exact owned hooks; bounded so a refusal cannot loop.
    cf_uh_count=0
    while [ "$cf_uh_count" -lt 8 ] && cf_table "$1" -t mangle -C FORWARD $CF_ACCT_HOOK -j "$CF_ACCT_CHAIN" >/dev/null 2>&1;do
        cf_table "$1" -t mangle -D FORWARD $CF_ACCT_HOOK -j "$CF_ACCT_CHAIN" || return 1
        cf_uh_count=$((cf_uh_count + 1))
    done
}

# Called once from the confirmed-apply hook under the mutation lock. Idempotent:
# unchanged rules keep their counters. Failure never changes enforcement results.
cf_activity_apply() {
    cf_aa_plan=$(cf_acct_plan) || return 1
    cf_aa_rebuild=0;cf_aa_old=0;cf_aa_stamps=;cf_aa_stamp=
    for cf_aa_f in 4 6;do
        cf_aa_want=$(printf '%s\n' "$cf_aa_plan" | awk -F '\t' -v f="$cf_aa_f" -v c="$CF_ACCT_CHAIN" '$1==f{print "-A " c " " $2}' | cf_normal_rules)
        if cf_aa_now=$(cf_acct_body "$cf_aa_f");then
            cf_aa_stamp=$(cf_acct_stamp "$cf_aa_now")
            [ -n "$cf_aa_stamp" ] || cf_aa_rebuild=1
            cf_aa_stamps="$cf_aa_stamps|$cf_aa_stamp"
            [ "$(printf '%s\n' "$cf_aa_now" | awk 'NR>1')" = "$cf_aa_want" ] || cf_aa_rebuild=1
            cf_aa_epoch=${cf_aa_stamp%% *}
            [ -z "$cf_aa_epoch" ] || [ "$cf_aa_epoch" -le "$cf_aa_old" ] || cf_aa_old=$cf_aa_epoch
        else cf_aa_rebuild=1;fi
    done
    cf_aa_restamp=0
    [ "$cf_aa_stamps" = "|$cf_aa_stamp|$cf_aa_stamp" ] || cf_aa_rebuild=1
    # Generation swaps recreate the blocked-rule counters this command reads.
    [ "${cf_aa_stamp#* }" = "$CF_SLOT" ] || cf_aa_restamp=1
    [ ! -e "$CF_RUNTIME/firewall.intent" ] || cf_aa_restamp=1
    if [ "$cf_aa_rebuild" = 1 ] || [ "$cf_aa_restamp" = 1 ];then
        # Never repeat: exceed both the persisted generation and any live stamp,
        # and durably record it before any counter object is reset or restamped.
        cf_aa_saved=$(cf_acct_epoch_read) || return 1
        [ "$cf_aa_saved" -le "$cf_aa_old" ] || cf_aa_old=$cf_aa_saved
        cf_aa_new=$((cf_aa_old + 1))
        [ "$CF_NOW_VALUE" -le "$cf_aa_new" ] || cf_aa_new=$CF_NOW_VALUE
        cf_durable_record "$CF_ACCT_EPOCH_FILE" "$cf_aa_new" || return 1
        for cf_aa_f in 4 6;do
            if [ "$cf_aa_rebuild" = 1 ];then
                if ! cf_table "$cf_aa_f" -t mangle -S "$CF_ACCT_CHAIN" >/dev/null 2>&1;then cf_table "$cf_aa_f" -t mangle -N "$CF_ACCT_CHAIN" || return 1;fi
                cf_table "$cf_aa_f" -t mangle -F "$CF_ACCT_CHAIN" || return 1
                cf_table "$cf_aa_f" -t mangle -A "$CF_ACCT_CHAIN" -m comment --comment "cfa/epoch/$cf_aa_new/$CF_SLOT" || return 1
                while IFS= read -r cf_aa_rule;do
                    [ -n "$cf_aa_rule" ] || continue
                    cf_table "$cf_aa_f" -t mangle -A "$CF_ACCT_CHAIN" $cf_aa_rule || return 1
                done <<EOA
$(printf '%s\n' "$cf_aa_plan" | awk -F '\t' -v f="$cf_aa_f" '$1==f{print $2}')
EOA
            else
                cf_table "$cf_aa_f" -t mangle -R "$CF_ACCT_CHAIN" 1 -m comment --comment "cfa/epoch/$cf_aa_new/$CF_SLOT" || return 1
            fi
        done
    fi
    for cf_aa_f in 4 6;do
        cf_acct_hook_ok "$cf_aa_f" && continue
        cf_acct_unhook "$cf_aa_f" && cf_table "$cf_aa_f" -t mangle -I FORWARD 1 $CF_ACCT_HOOK -j "$CF_ACCT_CHAIN" || return 1
    done
}
# Uninstall (remove-fw) calls this only after its refusal checks and proofs pass;
# the persisted epoch file is removed with the other runtime records.
cf_activity_remove_kernel() {
    for cf_ar_f in 4 6;do
        # A failed inspection is never absence; only a genuinely missing table is.
        if ! cf_ar_all=$(cf_table "$cf_ar_f" -t mangle -S 2>&1);then
            case $cf_ar_all in *"Table does not exist"*|*"can't initialize ip"*"table \`mangle'"*) continue;; esac
            cf_fail activity_cleanup_failed;return 1
        fi
        printf '%s\n' "$cf_ar_all" | awk -v c="$CF_ACCT_CHAIN" '$1=="-N"&&$2==c{yes=1}{for(i=1;i<NF;i++)if(($i=="-j"||$i=="-g")&&$(i+1)==c)yes=1}END{exit !yes}' || continue
        cf_acct_unhook "$cf_ar_f" || { cf_fail activity_cleanup_failed;return 1; }
        if printf '%s\n' "$cf_ar_all" | awk -v c="$CF_ACCT_CHAIN" '$1=="-N"&&$2==c{yes=1}END{exit !yes}';then
            cf_table "$cf_ar_f" -t mangle -F "$CF_ACCT_CHAIN" && cf_table "$cf_ar_f" -t mangle -X "$CF_ACCT_CHAIN" || { cf_fail activity_cleanup_failed;return 1; }
        fi
        cf_ar_all=$(cf_table "$cf_ar_f" -t mangle -S) || { cf_fail activity_cleanup_failed;return 1; }
        printf '%s\n' "$cf_ar_all" | awk -v c="$CF_ACCT_CHAIN" '$1=="-N"&&$2==c{exit 1}{for(i=1;i<NF;i++)if(($i=="-j"||$i=="-g")&&$(i+1)==c)exit 1}' || { cf_fail activity_cleanup_failed;return 1; }
    done
}

cf_activity_offload() {
    # fw3 treats an absent flow_offloading option in an existing defaults section as off.
    cf_ao_type=$(cf_backend uci -q get 'firewall.@defaults[0]' 2>/dev/null) || { printf '%s\n' unknown;return 0; }
    [ "$cf_ao_type" = defaults ] || { printf '%s\n' unknown;return 0; }
    cf_ao_state=off
    for cf_ao_key in flow_offloading flow_offloading_hw;do
        if cf_ao_value=$(cf_backend uci -q get "firewall.@defaults[0].$cf_ao_key" 2>/dev/null);then
            case $cf_ao_value in 1|on|true|yes|enabled)cf_ao_state=on;;0|off|false|no|disabled);;*)printf '%s\n' unknown;return 0;;esac
        fi
    done
    printf '%s\n' "$cf_ao_state"
}
cf_activity_neighbors() {
    # Raw states, including FAILED entries that enforcement attribution discards.
    cf_an_4=$(cf_backend ip -4 neigh show dev br-lan) || return 1
    cf_an_6=$(cf_backend ip -6 neigh show dev br-lan) || return 1
    printf '%s\n%s\n' "$cf_an_4" "$cf_an_6" | awk '{mac="";state="";for(i=2;i<=NF;i++){if($i=="lladdr"&&i<NF)mac=tolower($(i+1));if($i~/^(REACHABLE|PERMANENT|STALE|DELAY|PROBE|FAILED)$/)state=$i}if(mac~/^[0-9a-f][0-9a-f](:[0-9a-f][0-9a-f]){5}$/&&state!="")print "N\t" mac "\t" state}'
}
cf_activity_listing() {
    # -n -v -x: numeric, verbose, exact counters. Never -Z: reads never reset.
    cf_al_out=$(cf_table "$1" -t "$2" -nvxL "$3" 2>/dev/null) || return 1
    printf '%s\n' "$cf_al_out" | awk -v tag="$4" -v f="$1" 'NF{print tag "\t" f "\t" $0}'
}
cf_activity_json() {
    awk -F '\t' -v now="$1" -v offload="$2" -v slot="$3" -v errs="$4" -v max="$CF_ACCT_MAX_DEVICES" '
    function rank(s){return s=="REACHABLE"||s=="PERMANENT"?5:s=="DELAY"?4:s=="PROBE"?3:s=="STALE"?2:s=="FAILED"?1:0}
    function label(r){return r==5?"REACHABLE":r==4?"DELAY":r==3?"PROBE":r==2?"STALE":r==1?"FAILED":"ABSENT"}
    function err(code){if(!(code in seen)){seen[code]=1;ne++;elist[ne]=code}}
    function host(s){sub(/\/(32|128)$/,"",s);return tolower(s)}
    BEGIN{n=split(errs,a,"\n");for(i=1;i<=n;i++)if(a[i]!="")err(a[i])}
    $1=="D"{if(!($3 in dev)){if(nd>=max){err("devices_truncated");next}nd++;person[nd]=$2;mac[nd]=$3;dev[$3]=nd}next}
    $1=="A"{owner[$2]=$3;if(index($2,":")==0&&!($3 in ip))ip[$3]=$2;next}
    $1=="N"{r=rank($3);if(r>best[$2])best[$2]=r;next}
    $1=="S"{ps++;pmac=$2;next}
    $1=="C"{
        k=split($3,t," ");if(t[1]!~/^[0-9]+$/||t[2]!~/^[0-9]+$/)next
        c="";for(i=3;i<k;i++)if(t[i]=="/*"){c=t[i+1];break}
        m=split(c,p,"/");if(p[1]!="cfa")next
        if(p[2]=="epoch"&&m==4){if($2 in epoch)err("counter_epoch_ambiguous");epoch[$2]=p[3];stslot[$2]=p[4];next}
        if(!(p[3] in dev))next
        if(p[2]=="tx"&&m==3){txp[p[3]]+=t[1];txb[p[3]]+=t[2]}
        else if(p[2]=="rx"&&m==4){if(owner[p[4]]==p[3]){rxp[p[3]]+=t[1];rxb[p[3]]+=t[2]}else err("rx_mapping_stale")}
        next
    }
    $1=="B"{
        k=split($3,t," ");if(t[1]!~/^[0-9]+$/||t[3]!="REJECT")next
        who="";kind=""
        for(i=4;i<k;i++){
            if(t[i]=="MAC"){who=tolower(t[i+1]);kind="mac";break}
            if(t[i]=="match-set"){kind=(t[i+1]=="cf2_" slot "_p"&&t[i+2]=="src")?"pause":"other";break}
        }
        if(kind==""){for(i=4;i<=k;i++)if(t[i]~/[.:]/&&t[i]~/^[0-9a-fA-F:.\/]+$/){if(t[i-1]=="br-lan"&&i<k&&t[i+1]!~/^(0\.0\.0\.0|::)\/0$/){kind="dst";who=owner[host(t[i+1])]}break}}
        if(kind=="pause"){if(ps==1)who=pmac;else if(t[1]>0)err("blocked_unattributed")}
        if(kind=="mac"||kind=="dst"||kind=="pause"){if(who in dev)blocked[who]+=t[1];else if(t[1]>0&&kind!="mac")err("blocked_unattributed")}
        next
    }
    END{
        ce=0
        if(!("4" in epoch)||!("6" in epoch))err("accounting_unavailable")
        else if(epoch[4]!=epoch[6]||stslot[4]!=stslot[6])err("counter_epoch_ambiguous")
        else{ce=epoch[4];if(stslot[4]!=slot)err("counter_epoch_stale")}
        printf "{\"version\":1,\"router_epoch\":%s,\"counter_epoch\":%s,\"offload\":\"%s\",\"devices\":[",now,ce,offload
        for(i=1;i<=nd;i++){
            x=mac[i];addr=(x in ip)?"\"" ip[x] "\"":"null"
            printf "%s{\"person\":\"%s\",\"mac\":\"%s\",\"ip\":%s,\"neighbor\":\"%s\",\"tx_bytes\":%.0f,\"rx_bytes\":%.0f,\"tx_packets\":%.0f,\"rx_packets\":%.0f,\"blocked_packets\":%.0f}",(i>1?",":""),person[i],x,addr,label(best[x]+0),txb[x]+0,rxb[x]+0,txp[x]+0,rxp[x]+0,blocked[x]+0
        }
        printf "],\"errors\":["
        for(i=1;i<=ne;i++)printf "%s\"%s\"",(i>1?",":""),elist[i]
        print "]}"
    }'
}
# Read-only: no lock, no runtime writes, no kernel mutation.
cf_activity_collect() {
    cf_ac_errors=
    cf_ac_now=0
    if cf_clock;then cf_ac_now=$CF_NOW_VALUE;else cf_ac_errors="$cf_ac_errors
invalid_clock";fi
    [ ! -d "$CF_RUNTIME/lock" ] || cf_ac_errors="$cf_ac_errors
operation_in_progress"
    cf_slot_load
    cf_ac_offload=$(cf_activity_offload)
    cf_ac_devices=$(cf_acct_devices)
    cf_ac_macs=$(printf '%s\n' "$cf_ac_devices" | awk -F '\t' 'NF==2{print $2}')
    cf_ac_pairs=
    if [ -n "$cf_ac_macs" ];then cf_ac_pairs=$(cf_acct_pairs "$cf_ac_macs") || { cf_ac_pairs=;cf_ac_errors="$cf_ac_errors
address_inspection_failed"; };fi
    cf_ac_neigh=$(cf_activity_neighbors) || { cf_ac_neigh=;cf_ac_errors="$cf_ac_errors
neighbor_inspection_failed"; }
    cf_ac_acct=
    for cf_ac_f in 4 6;do
        cf_ac_rows=$(cf_activity_listing "$cf_ac_f" mangle "$CF_ACCT_CHAIN" C) && cf_ac_acct="$cf_ac_acct
$cf_ac_rows"
        cf_acct_hook_ok "$cf_ac_f" || cf_ac_errors="$cf_ac_errors
accounting_hook_missing"
    done
    cf_ac_block=
    if cf_ownership_valid;then
        for cf_ac_f in 4 6;do
            if cf_ac_rows=$(cf_activity_listing "$cf_ac_f" filter "cf2_${CF_SLOT}_f" B);then cf_ac_block="$cf_ac_block
$cf_ac_rows";else cf_ac_errors="$cf_ac_errors
blocked_counters_unavailable";fi
        done
        cf_ac_paused=$(cf_set_members "cf2_${CF_SLOT}_p") || { cf_ac_paused=;cf_ac_errors="$cf_ac_errors
blocked_counters_unavailable"; }
    else cf_ac_paused=;cf_ac_errors="$cf_ac_errors
blocked_counters_unavailable";fi
    {
        printf '%s\n' "$cf_ac_devices" | awk -F '\t' 'NF==2{print "D\t" $1 "\t" $2}'
        printf '%s\n' "$cf_ac_pairs" | awk -F '\t' 'NF==2{print "A\t" $1 "\t" $2}'
        printf '%s\n' "$cf_ac_neigh"
        printf '%s\n' "$cf_ac_paused" | awk 'NF{print "S\t" $1}'
        printf '%s\n' "$cf_ac_acct" "$cf_ac_block"
    } | cf_activity_json "$cf_ac_now" "$cf_ac_offload" "$CF_SLOT" "$cf_ac_errors"
}
cf_activity_refuse() {
    printf '{"version":1,"router_epoch":0,"counter_epoch":0,"offload":"unknown","devices":[],"errors":["%s"]}\n' "${CF_ERROR:-activity_unavailable}"
    return 1
}
cf_activity_output() {
    cf_ao_json=$(cf_activity_collect) || { cf_fail activity_failed;cf_activity_refuse;return 1; }
    # Like status, uncertainty is reported in errors with a zero exit.
    printf '%s\n' "$cf_ao_json"
}
cf_activity() {
    CF_SCOPE=
    cf_control_dirs && cf_state_load && cf_protected_valid && cf_policy_safe || { cf_activity_refuse;return 1; }
    cf_activity_output
}
cf_rpc_activity() {
    # Mirrors rpc-status admission without its mutation lock.
    CF_METADATA=;CF_GENERATION=;CF_CURRENT=;CF_POLICY=;CF_DIGEST=
    cf_install_gate rpc-activity && cf_control_dirs && cf_state_load || { cf_activity_refuse;return 1; }
    [ -n "$CF_GENERATION" ] || { cf_fail rpc_disabled;cf_activity_refuse;return 1; }
    cf_private_dir "$CF_RUNTIME" && cf_protected_valid && cf_policy_safe || { cf_activity_refuse;return 1; }
    cf_activity_output
}
