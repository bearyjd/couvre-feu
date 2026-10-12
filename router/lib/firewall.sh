# shellcheck disable=SC2034,SC2015,SC2086,SC2046
# Cross-module globals; A && B || fail intentionally rejects either failure.
# Isolated fw3/iptables/ipset backend. Every command is an argument vector.
CF_IPV6_OK=false
CF_CONNTRACK_OK=false
CF_NATIVE_OK=false
CF_ADDRESS_OK=false
CF_ADDRESS_DATA=
CF_LAN_IP=
CF_ROUTER6=

cf_ipv4_valid() { printf '%s\n' "$1" | awk '{n=split($0,a,".");if(n!=4)exit 1;for(i=1;i<=4;i++)if(a[i]!~/^(0|[1-9][0-9]*)$/||length(a[i])>3||a[i]+0>255)exit 1}'; }
cf_network() {
    CF_LAN_IP=$(cf_backend uci -q get network.lan.ipaddr 2>/dev/null) || CF_LAN_IP=192.168.1.1
    cf_ipv4_valid "$CF_LAN_IP" || { cf_fail invalid_lan_address; return 1; }
    cf_addr4=$(cf_backend ip -4 addr show dev br-lan) || { cf_fail lan_inspection_failed; return 1; }
    printf '%s\n' "$cf_addr4" | awk -v ip="$CF_LAN_IP" '{for(i=1;i<NF;i++)if($i=="inet"){split($(i+1),a,"/");if(a[1]==ip)yes=1}}END{exit !yes}' || { cf_fail lan_address_mismatch; return 1; }
    cf_addr6=$(cf_backend ip -6 addr show dev br-lan) || { cf_fail ipv6_inspection_failed; return 1; }
    CF_ROUTER6=$(printf '%s\n' "$cf_addr6" | awk '
    function valid(s,a,n,i,t,k){if(s!~/^[0-9a-f:]+$/||length(s)>39||index(s,":::")||!index(s,":"))return 0;k=index(s,"::");if(k&&index(substr(s,k+2),"::"))return 0;if((substr(s,1,1)==":"&&substr(s,1,2)!="::")||(substr(s,length(s),1)==":"&&substr(s,length(s)-1,2)!="::"))return 0;n=split(s,a,":");for(i=1;i<=n;i++)if(a[i]!=""){if(length(a[i])>4)return 0;t++}return k?t<8:t==8}
    {for(i=1;i<NF;i++)if($i=="inet6"){split($(i+1),a,"/");if(valid(a[1])&&a[1]!="::1"&&a[1]!="::")print a[1]}}' | sort -u)
}
cf_schedule_specs() {
    printf '%s\n' "$CF_POLICY" | awk -F '\t' '
    function secs(t,a){split(t,a,":");return (a[1]+0)*3600+(a[2]+0)*60}
    function clock(s){return sprintf("%02d:%02d:%02d",int(s/3600),int(s/60)%60,s%60)}
    function rotate(days,a,n,i,j,d,out,mark,sep){n=split(days,a,",");split("Mon Tue Wed Thu Fri Sat Sun",d," ");for(i=1;i<=n;i++)for(j=1;j<=7;j++)if(a[i]==d[j])mark[j%7+1]=1;for(j=1;j<=7;j++)if(mark[j]){sep="";if(out!="")sep=",";out=out sep d[j]}return out}
    function emit(p,m,d,s,e,n){n=++number[p];printf "cf_sched_%s_%d\t%s\t%s\t%s\t%s\t%s\n",p,n,p,m,d,clock(s),clock(e)}
    $1=="P"&&$3!="-"{mac[$2]=mac[$2] " " $3}
    $1=="S"{s=secs($5);e=secs($6);n=split(mac[$2],a," ");for(i=1;i<=n;i++)if(a[i]!=""){if(s<e)emit($2,a[i],$4,s,e-1);else{emit($2,a[i],$4,s,86399);if(e>0)emit($2,a[i],rotate($4),0,e-1)}}}'
}
cf_policy_plan() {
    cf_network || return 1
    cf_specs=$(cf_schedule_specs) || return 1
    cf_plan_pairs=$CF_ADDRESS_DATA

    cf_plan_paused=$(cf_effective_macs)
    for cf_family in 4 6; do
        # Explicit protected destination exclusions precede every inbound curfew rule.
        printf '%s\n' "$cf_plan_pairs" | awk -F '\t' -v family="$cf_family" '$1=="PROTECTED"&&((index($2,":")>0)==(family==6)){printf "%s\tfilter\tcf_fwd\t-o br-lan -d %s -m comment --comment cf:v1 -j RETURN\n",family,$2}'
        printf '%s\n' "$cf_plan_pairs" | awk -F '\t' -v family="$cf_family" -v paused="$cf_plan_paused" 'BEGIN{n=split(paused,a,"\n");for(i=1;i<=n;i++)p[a[i]]=1}NF==2&&p[$2]&&((index($1,":")>0)==(family==6)){printf "%s\tfilter\tcf_fwd\t-o br-lan -d %s -m comment --comment cf:v1 -j REJECT\n",family,$1}'
        printf '%s\tfilter\tcf_fwd\t-i br-lan -m set --match-set cf_paused src -m comment --comment cf:v1 -j REJECT\n' "$cf_family"
        printf '%s\n' "$cf_specs" | while IFS="$(printf '\t')" read -r cf_name cf_person cf_mac cf_days cf_start cf_stop; do
            [ -n "$cf_name" ] || continue
            printf '%s\tfilter\tcf_fwd\t-i br-lan -m mac --mac-source %s -m time --weekdays %s --timestart %s --timestop %s --kerneltz -m comment --comment cf:v1 -j REJECT\n' "$cf_family" "$cf_mac" "$cf_days" "$cf_start" "$cf_stop"
            cf_schedule_ips=$(printf '%s\n' "$cf_plan_pairs" | awk -F '\t' -v m="$cf_mac" -v f="$cf_family" 'NF==2&&$2==m&&((index($1,":")>0)==(f==6)){print $1}')
            for cf_schedule_ip in $cf_schedule_ips;do
                printf '%s\tfilter\tcf_fwd\t-o br-lan -d %s -m time --weekdays %s --timestart %s --timestop %s --kerneltz -m comment --comment cf:v1 -j REJECT\n' "$cf_family" "$cf_schedule_ip" "$cf_days" "$cf_start" "$cf_stop"
            done
        done
        for cf_proto in tcp udp; do
            printf '%s\tfilter\tcf_fwd\t-i br-lan -m set --match-set cf_kids src -p %s --dport 853 -m comment --comment cf:v1 -j REJECT\n' "$cf_family" "$cf_proto"
        done
        for cf_port in 784 8853; do
            printf '%s\tfilter\tcf_fwd\t-i br-lan -m set --match-set cf_kids src -p udp --dport %s -m comment --comment cf:v1 -j REJECT\n' "$cf_family" "$cf_port"
        done
        if [ "$cf_family" = 4 ]; then cf_doh_set=cf_doh;else cf_doh_set=cf_doh6;fi
        printf '%s\tfilter\tcf_fwd\t-i br-lan -m set --match-set cf_kids src -m set --match-set %s dst -m comment --comment cf:v1 -j REJECT\n' "$cf_family" "$cf_doh_set"
        if [ "$cf_family" = 6 ]; then
            for cf_proto in tcp udp; do
                printf '6\tfilter\tcf_fwd\t-i br-lan -m set --match-set cf_kids src -p %s --dport 53 -m comment --comment cf:v1 -j REJECT\n' "$cf_proto"
            done
            printf '%s\n' "$CF_ROUTER6" | while IFS= read -r cf_router; do
                [ -n "$cf_router" ] || continue
                printf '6\tfilter\tcf_input\t-i br-lan -m set --match-set cf_kids src -p udp -d %s --dport 53 -m comment --comment cf:v1 -j ACCEPT\n' "$cf_router"
            done
        else
            printf '4\tfilter\tcf_input\t-i br-lan -m set --match-set cf_kids src -p udp -d %s --dport 53 -m comment --comment cf:v1 -j ACCEPT\n' "$CF_LAN_IP"
            for cf_proto in tcp udp; do
                printf '4\tnat\tcf_dns\t-i br-lan -m set --match-set cf_kids src -p %s ! -d %s --dport 53 -m comment --comment cf:v1 -j DNAT --to-destination %s:53\n' "$cf_proto" "$CF_LAN_IP" "$CF_LAN_IP"
            done
        fi
    done
}
cf_effective_macs() {
    printf '%s\n' "$CF_POLICY" | awk -F '\t' -v now="${CF_PREPARED_EPOCH:-$CF_EXPIRY_NOW}" '$1=="P"&&$3!="-"{mac[$2]=mac[$2] " " $3}$1=="A"&&($3==0||$3>now){paused[$2]=1}END{for(p in paused){n=split(mac[p],a," ");for(i=1;i<=n;i++)if(a[i]!="")print a[i]}}' | sort -u
}
cf_kids() { printf '%s\n' "$CF_POLICY" | awk -F '\t' '$1=="P"&&$3!="-"{print $3}' | sort -u; }
cf_desired_set() {
    case $1 in cf_kids)cf_kids;;cf_paused)cf_effective_macs;;cf_doh)printf '%s\n' "$CF_POLICY" | awk -F '\t' '$1=="D4"{print $2}' | sort -u;;cf_doh6)printf '%s\n' "$CF_POLICY" | awk -F '\t' '$1=="D6"{print $2}' | sort -u;;*)return 1;;esac
}
cf_effective_digest() {
    # Fresh address/protection evidence also invalidates unchanged reconciliation.
    { printf '%s\n' "$CF_DIGEST";cf_boot_id;cf_effective_macs;printf '%s\n' "$CF_EXPECTED" "$CF_ADDRESS_DATA";sha256sum "$CF_PROTECTED"; } | sha256sum | awk '{print $1}'
}
cf_table() {
    cf_t_family=$1;shift
    if [ "$cf_t_family" = 4 ];then cf_backend iptables -w 5 "$@";else cf_backend ip6tables -w 5 "$@";fi
    cf_t_result=$?
    if [ "$cf_t_result" = 0 ] && [ "${3-}" != -S ];then
        cf_t_operation=${3-};cf_t_operation=${cf_t_operation#-}
        case ${3-} in -A|-I|-R|-D|-F|-X|-N)cf_rpc_checkpoint "after_${cf_t_family}_${4}_${cf_t_operation}";;esac
    fi
    return "$cf_t_result"
}
cf_normal_rules() {
    # iptables serializes built-in selectors before modules, uppercases MACs,
    # inserts protocol modules and prints default REJECT options. Canonicalize
    # complete option fragments; retain all unrecognized fragments as drift.
    awk '
    function days(s,a,d,n,i,j,out,mark,sep){n=split(s,a,",");split("Mon Tue Wed Thu Fri Sat Sun",d," ");for(i=1;i<=n;i++)for(j=1;j<=7;j++)if(a[i]==d[j])mark[j]=1;for(j=1;j<=7;j++)if(mark[j]){sep="";if(out!="")sep=",";out=out sep d[j]}return out}
    {
        gsub(/--comment "cf:v1"/,"--comment cf:v1");gsub(/--comment "cf:v2"/,"--comment cf:v2")
        if(index($0,"!fw3: ")) {gsub(/"/,"");for(i=1;i<NF;i++)if($i=="--mac-source")$(i+1)=tolower($(i+1));print;next}
        prefix=$1 " " $2;n=0;neg=""
        for(i=3;i<=NF;i++) {
            if($i=="!"){neg="! ";continue}
            key=$i
            if(key=="--kerneltz")part=key
            else if(key=="--match-set"){part=key " " $(i+1) " " $(i+2);i+=2}
            else if(substr(key,1,1)=="-"&&i<NF&&substr($(i+1),1,1)!="-") {
                v=$(++i)
                if(key=="-m"&&(v=="tcp"||v=="udp"))continue
                if(key=="--reject-with"&&(v=="icmp-port-unreachable"||v=="icmp6-port-unreachable"))continue
                if(key=="--mac-source")v=tolower(v)
                if(key=="--weekdays")v=days(v)
                if(key=="-d"||key=="-s"){
                    if(index(v,":"))sub(/\/128$/,"",v)
                    else sub(/\/32$/,"",v)
                }
                part=key " " v
            } else part=key
            fragment[++n]=neg part;neg=""
        }
        if(neg!="")fragment[++n]=neg
        for(i=1;i<=n;i++)for(j=i+1;j<=n;j++)if(fragment[i]>fragment[j]){t=fragment[i];fragment[i]=fragment[j];fragment[j]=t}
        out=prefix;for(i=1;i<=n;i++)out=out " " fragment[i];print out
    }'
}
cf_set_members() {
    cf_set_output=$(cf_backend ipset save "$1" 2>/dev/null) || { cf_fail set_inspection_failed;return 1; }
    printf '%s\n' "$cf_set_output" | awk -v name="$1" '$1=="add"&&$2==name{print tolower($3)}' | sort -u
}
cf_parent_order() {
    cf_chain_rules=$(cf_table "$1" -t "$2" -S "$3") || { cf_fail required_hook_missing;return 1; }
    printf '%s\n' "$cf_chain_rules" | awk -v mode=parent -v chain="$3" -v hook="$4" -f "$CF_LIB/rules.awk" || { cf_fail unsafe_parent_hook_semantics;return 1; }
}
cf_hook_args() {
    # forwarding must carry both LAN egress and WAN replies; rules guard each direction.
    if [ "$1" = cf_fwd ];then printf '%s\n' '-m comment --comment cf:v1';else printf '%s\n' '-i br-lan -m comment --comment cf:v1';fi
}
cf_reference_guard() {
    for cf_ref_f in 4 6;do
        cf_ref_lines=$(cf_table "$cf_ref_f" -t filter -S) || return 1
        cf_ref_norm=$(printf '%s\n' "$cf_ref_lines" | cf_normal_rules)
        for cf_ref_pair in 'forwarding_rule cf_fwd' 'input_rule cf_input';do
            # shellcheck disable=SC2086
            set -- $cf_ref_pair
            cf_ref_exact=$(printf '%s\n' "-A $1 $(cf_hook_args "$2") -j $2" | cf_normal_rules)
            printf '%s\n' "$cf_ref_norm" | awk -v c="$2" -v exact="$cf_ref_exact" '{for(i=1;i<NF;i++)if(($i=="-j"||$i=="-g")&&$(i+1)==c){if($0!=exact||++n>1)exit 1}}' || { cf_fail foreign_hook_collision;return 1; }
        done
    done
    cf_ref_lines=$(cf_table 4 -t nat -S) || return 1
    cf_ref_exact=$(printf '%s\n' '-A prerouting_rule -i br-lan -m comment --comment cf:v1 -j cf_dns' | cf_normal_rules)
    printf '%s\n' "$cf_ref_lines" | cf_normal_rules | awk -v exact="$cf_ref_exact" '{for(i=1;i<NF;i++)if(($i=="-j"||$i=="-g")&&$(i+1)=="cf_dns"){if($0!=exact||++n>1)exit 1}}' || { cf_fail foreign_hook_collision;return 1; }
}
cf_native_config_verify() {
    cf_config_specs=$(cf_schedule_specs) || return 1
    cf_config_names=$(printf '%s\n' "$cf_config_specs" | awk -F '\t' 'NF{print $1}' | sort)
    cf_config_lines=$(cf_backend uci -q show firewall) || { cf_fail native_metadata_inspection_failed;return 1; }
    # Unknown persistent selectors can narrow the next reload even while the
    # current kernel witness remains correct. Require the complete owned schema.
    printf '%s\n' "$cf_config_lines" | awk -v names="$cf_config_names" '
    BEGIN{n=split(names,a,"\n");for(i=1;i<=n;i++)if(a[i]!="")want[a[i]]=1}
    {eq=index($0,"=");if(!eq)next;k=substr($0,1,eq-1);n=split(k,a,".");if(a[1]!="firewall"||a[2]!~/^cf_sched_/)next
        if(!(a[2] in want)||n<2||n>3||seen[k]++)exit 2
        if(n==2){section[a[2]]=1;next}
        if(a[3]!~/^(couvrefeu_owner|name|src|dest|target|proto|src_mac|weekdays|start_time|stop_time|utc_time|enabled)$/)exit 2
    }
    END{for(name in want)if(!section[name])exit 2}' || { cf_fail native_metadata_drift;return 1; }
    cf_tab=$(printf '\t')
    while IFS="$cf_tab" read -r cf_name cf_person cf_mac cf_days cf_start cf_stop;do
        [ -n "$cf_name" ] || continue
        cf_config_type=$(cf_backend uci -q get "firewall.$cf_name") || { cf_fail native_metadata_inspection_failed;return 1; }
        [ "$cf_config_type" = rule ] || { cf_fail native_metadata_drift;return 1; }
        for cf_pair in 'couvrefeu_owner=v1' "name=$cf_name" 'src=lan' 'dest=wan' 'target=REJECT' 'proto=all' "src_mac=$cf_mac" "weekdays=$(printf '%s\n' "$cf_days" | tr ',' ' ')" "start_time=$cf_start" "stop_time=$cf_stop" 'utc_time=0' 'enabled=1';do
            cf_key=${cf_pair%%=*};cf_value=${cf_pair#*=}
            cf_actual=$(cf_backend uci -q get "firewall.$cf_name.$cf_key") || { cf_fail native_metadata_inspection_failed;return 1; }
            [ "$cf_actual" = "$cf_value" ] || { cf_fail native_metadata_drift;return 1; }
        done
    done <<EOF
$cf_config_specs
EOF
}
cf_native_apply() {
    cf_specs=$(cf_schedule_specs) || return 1
    cf_new_native=$(printf '%s\n' "$cf_specs" | sha256sum | awk '{print $1}')
    cf_old_native=
    if cf_safe_file "$CF_RUNTIME/firewall.snapshot";then cf_old_native=$(awk '/^SCHEDULE /{sub(/^SCHEDULE /,"");print}' "$CF_RUNTIME/firewall.snapshot" | sha256sum | awk '{print $1}');fi
    # Empty initial policy needs no UCI write or reload.
    if [ "$cf_new_native" = "$cf_old_native" ] || { [ -z "$cf_specs" ] && [ -z "$cf_uci_sections" ]; };then
        if cf_native_config_verify;then return 0;fi
        # Drift defeats the metadata shortcut and follows normal staged repair.
        CF_ERROR=
    fi
    cf_stage=$CF_RUNTIME/.uci.$$
    [ ! -e "$cf_stage" ] && [ ! -L "$cf_stage" ] || { cf_fail unsafe_staging;return 1; }
    mkdir -m 700 "$cf_stage" || return 1
    mkdir -m 700 "$cf_stage/.delta" || return 1
    [ -f "$CF_BASE/etc/config/firewall" ] && [ ! -L "$CF_BASE/etc/config/firewall" ] || { cf_fail missing_firewall_config;return 1; }
    cp -p "$CF_BASE/etc/config/firewall" "$cf_stage/firewall" || { cf_fail native_stage_failed;return 1; }
    for cf_section in $cf_uci_sections;do cf_backend uci -c "$cf_stage" -t "$cf_stage/.delta" delete "firewall.$cf_section" || { cf_fail native_stage_failed;return 1; };done
    cf_tab=$(printf '\t')
    while IFS="$cf_tab" read -r cf_name cf_person cf_mac cf_days cf_start cf_stop;do
        [ -n "$cf_name" ] || continue
        cf_backend uci -c "$cf_stage" -t "$cf_stage/.delta" set "firewall.$cf_name=rule" || return 1
        for cf_pair in "couvrefeu_owner=v1" "name=$cf_name" 'src=lan' 'dest=wan' 'target=REJECT' 'proto=all' "src_mac=$cf_mac" "weekdays=$(printf '%s\n' "$cf_days" | tr ',' ' ')" "start_time=$cf_start" "stop_time=$cf_stop" 'utc_time=0' 'enabled=1';do
            cf_backend uci -c "$cf_stage" -t "$cf_stage/.delta" set "firewall.$cf_name.$cf_pair" || { cf_fail native_stage_failed;return 1; }
        done
    done <<EOF
$cf_specs
EOF
    cf_backend uci -c "$cf_stage" -t "$cf_stage/.delta" commit firewall || { cf_fail native_stage_failed;return 1; }
    # The installer journals exact full-file bytes, so native updates never bless foreign drift.
    if [ -e "$CF_DIR/backup/ready" ];then
        cf_install_helper=$CF_BASE/usr/lib/couvrefeu/install-common.sh
        [ -f "$cf_install_helper" ] && [ ! -L "$cf_install_helper" ] || { cf_fail missing_install_journal;return 1; }
        cf_install_journal firewall-prepare "$cf_stage/firewall" || { cf_fail native_journal_failed;return 1; }
    fi
    mv -f "$cf_stage/firewall" "$CF_BASE/etc/config/firewall" || { cf_fail native_commit_failed;return 1; }
    rmdir "$cf_stage/.delta" && rmdir "$cf_stage" || return 1
    if [ -e "$CF_DIR/backup/ready" ];then cf_install_journal firewall-commit || { cf_fail native_journal_failed;return 1; };fi
    CF_RELOAD_TOKEN=$(printf '%s\n' "$$:$CF_DIGEST:$CF_NOW_VALUE" | sha256sum | awk '{print $1}')
    printf '%s\n' "$CF_RELOAD_TOKEN" > "$CF_RUNTIME/lock/reload" || return 1
    export CF_RELOAD_TOKEN
    cf_backend fw3 -q reload || { unset CF_RELOAD_TOKEN;cf_fail native_reload_failed;return 1; }
    unset CF_RELOAD_TOKEN
    rm -f "$CF_RUNTIME/lock/reload"
}
cf_flush_connections() {
    if [ -n "${CF_DRAIN_MACS+x}" ];then cf_paused=$CF_DRAIN_MACS;else cf_paused=$(cf_effective_blocked_macs) || return 1;fi
    cf_durable_record schedule.clock "$((CF_NOW_VALUE / 60)) $(date -d "@$CF_NOW_VALUE" '+%a-%H:%M:%S-%z')" || return 1
    [ -n "$cf_paused" ] || return 0
    cf_pairs=$CF_ADDRESS_DATA
    cf_ips=$(printf '%s\n' "$cf_pairs" | awk -F '\t' -v macs="$cf_paused" 'BEGIN{n=split(macs,a,"\n");for(i=1;i<=n;i++)m[a[i]]=1}NF==2&&m[$2]{print $1}' | sort -u)
    for cf_ip in $cf_ips;do
        case $cf_ip in *:*)cf_family=ipv6;;*)cf_family=ipv4;;esac
        for cf_direction in -s -d;do
            cf_out=$(cf_backend conntrack -D "$cf_direction" "$cf_ip" -f "$cf_family" 2>&1)
            cf_rc=$?
            if [ "$cf_rc" != 0 ];then
                # conntrack-tools returns 1 for a confirmed empty match; errors are not absence.
                if [ "$cf_rc" != 1 ] || ! printf '%s\n' "$cf_out" | awk '/^conntrack v[0-9][^:]*: 0 flow entries have been deleted\.$/{n++}END{exit n!=1||NR!=1}';then cf_fail conntrack_delete_failed;return 1;fi
            fi
        done
    done
}
cf_unchanged_verified() {
    cf_ownership_valid && cf_safe_file "$CF_RUNTIME/firewall.snapshot" && cf_safe_file "$CF_RUNTIME/confirmed" || return 1
    [ "$(wc -c < "$CF_RUNTIME/confirmed")" -le 160 ] || return 1
    for cf_pending in error firewall.intent firewall.cleanup;do
        [ ! -e "$CF_RUNTIME/$cf_pending" ] && [ ! -L "$CF_RUNTIME/$cf_pending" ] || return 1
    done
    cf_prior_confirmation=$(awk 'NR!=1||NF!=3||$1!~/^(0|[1-9][0-9]*)$/||length($1)>10||$1+0>2147483647||length($2)!=64||$2~/[^0-9a-f]/||length($3)!=64||$3~/[^0-9a-f]/{exit 2}{print}END{if(NR!=1)exit 2}' "$CF_RUNTIME/confirmed") || return 1
    [ "$cf_prior_confirmation" = "$CF_REVISION $CF_DIGEST $(cf_effective_digest)" ] || return 1
    cf_noop_snapshot=$(cf_snapshot) || return 1
    [ "$cf_noop_snapshot" = "$(awk '{print}' "$CF_RUNTIME/firewall.snapshot")" ] || return 1
    # Private metadata is only eligibility. Verify all actual kernel objects,
    # hook ordering and native persistent/kernel witnesses under the lock.
    cf_verify
}
cf_confirm_apply() {
    cf_rpc_checkpoint before_confirmation
    cf_ca_snapshot=$(cf_snapshot) || { cf_fail snapshot_failed;return 1; }
    cf_durable_record firewall.snapshot "$cf_ca_snapshot" || return 1
    if [ "${CF_CONSERVATIVE_RECOVERY:-0}" = 1 ];then
        cf_transition_phase rebase_ready
        return $?
    fi
    cf_durable_record confirmed "$CF_REVISION $CF_DIGEST $(cf_effective_digest)" || return 1
    cf_rpc_checkpoint after_confirmation
    [ ! -e "$CF_RUNTIME/error" ] || { cf_safe_file "$CF_RUNTIME/error" && rm -f "$CF_RUNTIME/error"; } || return 1
    if [ -e "$CF_RUNTIME/firewall.intent" ] || [ -L "$CF_RUNTIME/firewall.intent" ];then
        cf_safe_file "$CF_RUNTIME/firewall.intent" && rm -f "$CF_RUNTIME/firewall.intent" || return 1
    fi
    cf_backend sync
}
cf_native_reject_path() {
    if [ -z "${CF_WAN_DEVICES-}" ];then
        CF_WAN_DEVICES=$(cf_backend fw3 -q zone wan) || return 1
        [ "${#CF_WAN_DEVICES}" -le 1024 ] || return 1
        printf '%s\n' "$CF_WAN_DEVICES" | awk 'length($0)<1||length($0)>15||$0!~/^[a-zA-Z0-9_][a-zA-Z0-9_.:-]*$/||seen[$0]++{exit 1}NR>64{exit 1}END{if(NR<1)exit 1}' || return 1
    fi
    cf_dest_reject=$(cf_table "$1" -t filter -S zone_wan_dest_REJECT) || return 1
    printf '%s\n' "$cf_dest_reject" | awk -v mode=destreject -v chain=zone_wan_dest_REJECT -v family="$1" -v devices="$CF_WAN_DEVICES" -f "$CF_LIB/rules.awk" || return 1
    cf_reject=$(cf_table "$1" -t filter -S reject) || return 1
    printf '%s\n' "$cf_reject" | awk -v mode=reject -v chain=reject -v family="$1" -f "$CF_LIB/rules.awk"
}
cf_native_verify() {
    CF_WAN_DEVICES=
    cf_specs=$(cf_schedule_specs)
    CF_NATIVE_OK=true
    cf_native_config_verify || { CF_NATIVE_OK=false;return 1; }
    [ -n "$cf_specs" ] || return 0
    cf_tab=$(printf '\t')
    while IFS="$cf_tab" read -r cf_name cf_person cf_mac cf_days cf_start cf_stop;do
        [ -n "$cf_name" ] || continue
        for cf_f in 4 6;do
            cf_native_rules=$(cf_table "$cf_f" -t filter -S zone_lan_forward 2>/dev/null) || { CF_NATIVE_OK=false;cf_fail native_kernel_pending;return 1; }
            # Earlier ACCEPT/RETURN paths cannot shadow the named schedule.
            cf_native_prefix=$(printf '%s\n' "$cf_native_rules" | awk -v mode=prefix -v chain=zone_lan_forward -v name="$cf_name" -v mac="$cf_mac" -v days="$cf_days" -v start="$cf_start" -v stop="$cf_stop" -v family="$cf_f" -f "$CF_LIB/rules.awk") || { CF_NATIVE_OK=false;cf_fail native_kernel_pending;return 1; }
            for cf_prefix_chain in $cf_native_prefix;do
                if [ "$cf_prefix_chain" = zone_wan_dest_REJECT ];then
                    cf_native_reject_path "$cf_f" || { CF_NATIVE_OK=false;cf_fail native_kernel_pending;return 1; }
                else
                    cf_prefix_rules=$(cf_table "$cf_f" -t filter -S "$cf_prefix_chain") || { CF_NATIVE_OK=false;cf_fail native_kernel_pending;return 1; }
                    printf '%s\n' "$cf_prefix_rules" | awk -v mode=passthrough -v chain="$cf_prefix_chain" -f "$CF_LIB/rules.awk" || { CF_NATIVE_OK=false;cf_fail native_kernel_pending;return 1; }
                fi
            done
            # The complete supported native rule must match, with no extra selectors.
            cf_native_jump=$(printf '%s\n' "$cf_native_rules" | awk -v mode=native -v chain=zone_lan_forward -v name="$cf_name" -v mac="$cf_mac" -v days="$cf_days" -v start="$cf_start" -v stop="$cf_stop" -v family="$cf_f" -f "$CF_LIB/rules.awk") || { CF_NATIVE_OK=false;cf_fail native_kernel_pending;return 1; }
            case $cf_native_jump in
                REJECT) ;;
                zone_wan_dest_REJECT) cf_native_reject_path "$cf_f" || { CF_NATIVE_OK=false;cf_fail native_kernel_pending;return 1; };;
                *) CF_NATIVE_OK=false;cf_fail native_kernel_pending;return 1;;
            esac
        done
    done <<EOF
$cf_specs
EOF
}
cf_cleanup_verify() {
    cf_safe_file "$CF_RUNTIME/firewall.cleanup" && [ "$(wc -c < "$CF_RUNTIME/firewall.cleanup")" -le 524288 ] || { cf_fail unsafe_cleanup_intent;return 1; }
    cf_cleanup_saved=$(awk 'NR==1{if($0!="CLEANUP 1")exit 2;next}$1!~/^(CHAIN|RULE|IPSET)$/{exit 2}{print}' "$CF_RUNTIME/firewall.cleanup") || { cf_fail unsafe_cleanup_intent;return 1; }
    cf_cleanup_now=$(cf_cleanup_inventory) || { cf_fail cleanup_inspection_failed;return 1; }
    # Each approved object may remain unchanged, be flushed, or be absent. No additions.
    printf '%s\n' "$cf_cleanup_now" | awk -v saved="$cf_cleanup_saved" '
    BEGIN{n=split(saved,a,"\n");for(i=1;i<=n;i++){split(a[i],b," ");if(b[1]=="CHAIN"||b[1]=="RULE")k=b[2] " " b[3] " " b[4];else if(b[1]=="IPSET")k="set " b[2];else exit 2;old[k]=old[k] a[i] "\n"}}
    $1=="CLEANUP"{next}
    $1=="CHAIN"||$1=="RULE"{k=$2 " " $3 " " $4;now[k]=now[k] $0 "\n";if($1=="CHAIN")empty[k]=$0 "\n";next}
    $1=="IPSET"{k="set " $2;now[k]=now[k] $0 "\n";next}
    {exit 2}
    END{for(k in now)if(old[k]==""||(now[k]!=old[k]&&now[k]!=empty[k]))exit 1}' || { cf_fail cleanup_drift;return 1; }
    cf_reference_guard
}
cf_cleanup_begin() {
    cf_cleanup_data=$(cf_cleanup_inventory) || { cf_fail cleanup_inspection_failed;return 1; }
    cf_durable_record firewall.cleanup "$cf_cleanup_data"
}
cf_remove_one() {
    cf_remove_f=$1;cf_remove_t=$2;cf_remove_parent=$3;cf_remove_c=$4
    cf_remove_rules=$(cf_table "$1" -t "$2" -S "$3") || return 1
    cf_remove_exact=$(printf '%s\n' "-A $3 $(cf_hook_args "$4") -j $4" | cf_normal_rules)
    if printf '%s\n' "$cf_remove_rules" | cf_normal_rules | awk -v exact="$cf_remove_exact" '$0==exact{yes=1}END{exit !yes}';then
        # Fixed constant hook arguments are intentionally split.
        # shellcheck disable=SC2086,SC2046
        cf_table "$cf_remove_f" -t "$cf_remove_t" -D "$cf_remove_parent" $(cf_hook_args "$cf_remove_c") -j "$cf_remove_c" || return 1
    fi
    cf_remove_inventory=$(cf_table "$cf_remove_f" -t "$cf_remove_t" -S) || return 1
    if printf '%s\n' "$cf_remove_inventory" | awk -v c="$cf_remove_c" '$1=="-N"&&$2==c{yes=1}END{exit !yes}';then
        cf_table "$cf_remove_f" -t "$cf_remove_t" -F "$cf_remove_c" && cf_table "$cf_remove_f" -t "$cf_remove_t" -X "$cf_remove_c" || return 1
    fi
}

# Two immutable bounded generations. Durable acceptance and exposure are separate.
CF_SLOT=a
CF_GUARDED=0
cf_slot_load() {
    CF_SLOT=a
    if cf_safe_file "$CF_RUNTIME/firewall.owned";then
        cf_slot_value=$(awk 'NR==2&&($0=="a"||$0=="b"){print}' "$CF_RUNTIME/firewall.owned")
        [ -z "$cf_slot_value" ] || CF_SLOT=$cf_slot_value
    fi
}
cf_ownership_valid() {
    cf_safe_file "$CF_RUNTIME/firewall.owned" || return 1
    awk 'NR==1&&$0!="couvrefeu-owned-v2"{exit 2}NR==2&&$0!~/^[ab]$/{exit 2}NR>2{exit 2}END{if(NR!=2)exit 2}' "$CF_RUNTIME/firewall.owned"
}
cf_plan() {
    cf_pl_raw=$(cf_policy_plan) || return 1
    printf '%s\n' "$cf_pl_raw" | awk -F '\t' -v s="$CF_SLOT" 'BEGIN{OFS="\t"}
    {gsub(/cf_paused/,"cf2_" s "_p",$4);gsub(/cf_kids/,"cf2_" s "_k",$4);gsub(/cf_doh6/,"cf2_" s "_d6",$4);gsub(/cf_doh/,"cf2_" s "_d4",$4);gsub(/cf:v1/,"cf:v2",$4);
    if($3=="cf_fwd")$3="cf2_" s "_f";else if($3=="cf_input")$3="cf2_" s "_i";else $3="cf2_" s "_d";print}
    END{for(f=4;f<=6;f+=2){print f,"filter","cf2_" s "_f","-m comment --comment cf:v2 -j RETURN";print f,"filter","cf2_" s "_i","-m comment --comment cf:v2 -j RETURN"}print 4,"nat","cf2_" s "_d","-m comment --comment cf:v2 -j RETURN"}'
}
cf_effective_blocked_macs() {
    # Kernel windows remain authoritative. Minute cron only evicts accelerated flows.
    cf_local_clock=$(date -d "@$CF_NOW_VALUE" '+%a %H:%M:%S') || return 1
    cf_local_day=${cf_local_clock%% *};cf_local_time=${cf_local_clock#* }
    { cf_effective_macs;cf_schedule_specs | awk -F '\t' -v day="$cf_local_day" -v clock="$cf_local_time" 'index("," $4 ",","," day ",")&&clock>=$5&&clock<=$6{print $3}'; } | sort -u
}
cf_slot_sets() { printf '%s\n' "cf2_$1" | awk '{for(i=1;i<=5;i++){split("k p d4 d6 u",a," ");print $0 "_" a[i]}}'; }
cf_slot_chains() {
    for cf_sc_f in 4 6;do
        for cf_sc_c in f i g;do printf '%s filter cf2_%s_%s\n' "$cf_sc_f" "$1" "$cf_sc_c";done
    done
    printf '4 nat cf2_%s_d\n' "$1"
}
cf_owned_chain() { case "$1:$2:$3" in [46]:filter:cf_fwd|[46]:filter:cf_input|4:nat:cf_dns|[46]:filter:cf2_[ab]_[fig]|4:nat:cf2_[ab]_d)return 0;;*)return 1;;esac; }
cf_owned_set() { case $1 in cf2_[ab]_k|cf2_[ab]_p|cf2_[ab]_d4|cf2_[ab]_d6|cf2_[ab]_u)return 0;;*)return 1;;esac; }
cf_rules_snapshot() {
    for cf_rs_pair in '4 filter' '6 filter' '4 nat';do
        set -- $cf_rs_pair
        cf_rs_lines=$(cf_table "$1" -t "$2" -S) || return 1
        printf '%s\n' "$cf_rs_lines" | cf_normal_rules | awk -v f="$1" -v t="$2" '($1=="-A"||$1=="-N")&&((t=="filter"&&$2~/^(cf_fwd|cf_input|cf2_[ab]_[fig])$/)||(f==4&&t=="nat"&&$2~/^(cf_dns|cf2_[ab]_d)$/)){print f " " t " " $2 " " $0}'
    done
}
cf_snapshot() {
    cf_ss_rules=$(cf_rules_snapshot) || return 1
    printf '%s\n' "$cf_ss_rules" | awk 'NF{print "RULE " $0}'
    cf_ss_sets=$(cf_backend ipset save) || return 1
    printf '%s\n' "$cf_ss_sets" | awk '$1=="create"&&$2~/^cf2_[ab]_(k|p|d4|d6|u)$/{type[$2]=$3;family[$2]="inet";for(i=4;i<NF;i++)if($i=="family")family[$2]=$(i+1)}$1=="add"&&$2~/^cf2_[ab]_(k|p|d4|d6|u)$/{member[$2]=member[$2] tolower($3) "\n"}END{for(s in type){print "SETDEF " s " " type[s] " " family[s];n=split(member[s],a,"\n");for(i=1;i<=n;i++)if(a[i]!="")print "SET " s " " a[i]}}' | sort -k2,2 -k1,1r -k3,3
    cf_schedule_specs | awk -F '\t' 'NF{print "SCHEDULE " $0}'
}
cf_durable_record() {
    cf_dr_name=$1;cf_dr_data=$2;cf_dr_temp=$CF_RUNTIME/.intent.$$
    [ ! -e "$cf_dr_temp" ] && [ ! -L "$cf_dr_temp" ] || { cf_fail unsafe_temporary;return 1; }
    [ "${#cf_dr_data}" -le 524288 ] || { cf_fail transition_too_large;return 1; }
    platform_initial_write
    printf '%s\n' "$cf_dr_data" > "$cf_dr_temp" && chmod 600 "$cf_dr_temp" && cf_backend sync && mv -f "$cf_dr_temp" "$CF_RUNTIME/$cf_dr_name" && cf_backend sync || { cf_fail transition_journal_failed;return 1; }
}
cf_boot_id() {
    if [ "$CF_LOCAL_TEST" = 1 ];then printf '%s\n' "${CF_TEST_BOOT_ID:-fixture-boot}";else awk 'NR==1{print}' /proc/sys/kernel/random/boot_id;fi
}
cf_transition_phase() {
    CF_TRANSITION=$(printf '%s\n' "$CF_TRANSITION" | awk -v p="$1" '/^PHASE /{print "PHASE " p;next}{print}')
    cf_durable_record firewall.intent "$CF_TRANSITION" || return 1
    cf_rpc_checkpoint "transition_$1"
}
cf_transition_read() {
    cf_safe_file "$CF_RUNTIME/firewall.intent" && [ "$(wc -c < "$CF_RUNTIME/firewall.intent")" -le 524288 ] || { cf_fail unsafe_transition;return 1; }
    CF_TRANSITION=$(awk '
    function chain(c,f,t){return t=="filter"&&f~/^[46]$/&&c~/^(cf_fwd|cf_input|cf2_[ab]_[fig])$/||f==4&&t=="nat"&&c~/^(cf_dns|cf2_[ab]_d)$/}
    function rule(s,a,n,i){if(s!~/^[a-zA-Z0-9_:.,! \/-]+$/)return 0;n=split(s,a," ");for(i=1;i<=n;i++)if(substr(a[i],1,1)=="-"&&!index(" -i -o -d -p -m --match-set --comment -j --dport --mac-source --weekdays --timestart --timestop --kerneltz --to-destination "," " a[i] " "))return 0;return index(s,"--comment cf:v2")>0}
    NF==0{next}
    NR==1&&$0!="TRANSITION 2"{exit 2}
    $1=="SLOT"{if($2!~/^[ab]$/||NF!=2)exit 2;s=$2}
    $1~/^(OLD|NEW|PROTECTION|NATIVE_OLD|NATIVE_NEW)$/&&(NF!=2||length($2)!=64||$2~/[^0-9a-f]/){exit 2}
    $1=="EPOCH"&&(NF!=2||$2!~/^(0|[1-9][0-9]*)$/||length($2)>10||$2+0>2147483647){exit 2}
    $1~/^(TRANSITION|SLOT|OLD|NEW|GENERATION|RECEIPT|OLD_RECEIPT|EPOCH|NATIVE_OLD|NATIVE_NEW|BOOT|PHASE|PROTECTION)$/&&seen[$1]++{exit 2}
    $1~/^(PLAN|GUARD|REPAIR)$/ {
        n=split($0,p,"\t");if(n!=5||!chain(p[4],p[2],p[3])||!rule(p[5]))exit 2
        if($1=="PLAN"&&p[4]!="cf2_" s "_f"&&p[4]!="cf2_" s "_i"&&p[4]!="cf2_" s "_d")exit 2
        if($1=="GUARD"&&p[4]!="cf2_" s "_g")exit 2
        if($1=="REPAIR"&&p[4]!~/^cf2_[ab]_[fg]$/)exit 2
    }
    $1~/^(BEFORE|AFTER|REPAIRED|REPAIR_BEFORE)$/ {
        if($2=="RULE"){if(!chain($5,$3,$4)||$6!~/^-(A|N)$/||$7!=$5)exit 2}
        else if($2~/^(SETDEF|SET)$/){if($3!~/^cf2_[ab]_(k|p|d4|d6|u)$/)exit 2}
        else if($2!="SCHEDULE")exit 2
    }
    $1!~/^(TRANSITION|SLOT|OLD|NEW|GENERATION|RECEIPT|OLD_RECEIPT|EPOCH|NATIVE_OLD|NATIVE_NEW|BOOT|PHASE|PROTECTION|ADDRESS|UNION|PLAN|BEFORE|AFTER|REPAIRED|REPAIR_BEFORE|REPAIR|GUARD)$/{exit 2}
    {print}
    END{if(NR<8||seen["SLOT"]!=1||seen["OLD"]!=1||seen["NEW"]!=1||seen["EPOCH"]!=1||seen["GENERATION"]!=1||seen["PROTECTION"]!=1)exit 2}' "$CF_RUNTIME/firewall.intent") || { cf_fail unsafe_transition;return 1; }
    CF_SLOT=$(printf '%s\n' "$CF_TRANSITION" | awk '$1=="SLOT"{print $2}')
    case $CF_SLOT in a|b);;*)cf_fail unsafe_transition;return 1;;esac
    cf_tr_generation=$(printf '%s\n' "$CF_TRANSITION" | awk '$1=="GENERATION"{print $2}')
    [ "$cf_tr_generation" = "${CF_GENERATION:--}" ] || { cf_fail transition_generation_mismatch;return 1; }
    CF_EXPECTED=$(printf '%s\n' "$CF_TRANSITION" | awk '/^PLAN\t/{sub(/^PLAN\t/,"");print}')
    CF_GUARD_PLAN=$(printf '%s\n' "$CF_TRANSITION" | awk '/^GUARD\t/{sub(/^GUARD\t/,"");print}')
    CF_UNION=$(printf '%s\n' "$CF_TRANSITION" | awk '$1=="UNION"{print $2}')
}
cf_inventory_plan() {
    cf_ip_plan=$1
    printf '%s\n' "$cf_ip_plan" | awk -F '\t' 'NF==4{if(!seen[$1 FS $2 FS $3]++)print "RULE " $1 " " $2 " " $3 " -N " $3;print "RULE " $1 " " $2 " " $3 " -A " $3 " " $4}' | while IFS= read -r cf_ip_line;do
        cf_ip_head=$(printf '%s\n' "$cf_ip_line" | awk '{print $1 " " $2 " " $3 " " $4}')
        cf_ip_body=$(printf '%s\n' "$cf_ip_line" | awk '{$1=$2=$3=$4="";sub(/^ +/,"");print}' | cf_normal_rules)
        printf '%s %s\n' "$cf_ip_head" "$cf_ip_body"
    done
}
cf_dispatch_plan() {
    for cf_dp_f in 4 6;do
        printf '%s\tfilter\tcf_fwd\t-m comment --comment cf:v2 -j cf2_%s_f\n' "$cf_dp_f" "$1"
        printf '%s\tfilter\tcf_input\t-m comment --comment cf:v2 -j cf2_%s_i\n' "$cf_dp_f" "$1"
    done
    printf '4\tnat\tcf_dns\t-m comment --comment cf:v2 -j cf2_%s_d\n' "$1"
}
cf_transition_inventory_check() {
    cf_tic_current=$(cf_snapshot) || return 1
    cf_tic_before=$(printf '%s\n' "$CF_TRANSITION" | awk '/^BEFORE /{sub(/^BEFORE /,"");print}')
    cf_tic_repair_before=$(printf '%s\n' "$CF_TRANSITION" | awk '/^REPAIR_BEFORE /{sub(/^REPAIR_BEFORE /,"");print}')
    cf_tic_repaired=$(printf '%s\n' "$CF_TRANSITION" | awk '/^REPAIRED /{sub(/^REPAIRED /,"");print}')
    cf_tic_after=$(printf '%s\n' "$CF_TRANSITION" | awk '/^AFTER /{sub(/^AFTER /,"");print}')
    # Only exactly recorded chain bodies, ordered staging prefixes and complete
    # dispatch targets can survive a crash. Foreign additions never authorize cleanup.
    printf '%s' "$cf_tic_current" | awk -v before="$cf_tic_before" -v repaired="$cf_tic_repaired" -v repair_before="$cf_tic_repair_before" -v after="$cf_tic_after" -v slot="$CF_SLOT" -v phase="$(printf '%s\n' "$CF_TRANSITION" | awk '$1=="PHASE"{print $2}')" '
    function key(line,a){split(line,a," ");if(a[1]=="RULE")return "chain " a[2] " " a[3] " " a[4];if(a[1]=="SETDEF"||a[1]=="SET")return "set " a[2];return ""}
    BEGIN{n=split(before,a,"\n");for(i=1;i<=n;i++){k=key(a[i]);if(k!="")old[k]=old[k] a[i] "\n"}n=split(after,a,"\n");for(i=1;i<=n;i++){k=key(a[i]);if(k!="")new[k]=new[k] a[i] "\n"}n=split(repaired,a,"\n");for(i=1;i<=n;i++){k=key(a[i]);if(k!="")fix[k]=fix[k] a[i] "\n"}n=split(repair_before,a,"\n");for(i=1;i<=n;i++){k=key(a[i]);if(k!="")pre[k]=pre[k] a[i] "\n"}}
    $1=="SCHEDULE"{next}
    {k=key($0);if(k=="")exit 2;now[k]=now[k] $0 "\n";if($1=="RULE")rules++
        if($1=="RULE"&&$4~/^(cf_fwd|cf_input|cf_dns)$/)for(i=5;i<NF;i++)if(($i=="-j"||$i=="-g")&&$(i+1)~("^cf2_" slot "_[figd]$"))reachable=1}
    END{for(k in now){if(now[k]==old[k]||now[k]==new[k]||now[k]==fix[k]||now[k]==pre[k])continue
        split(k,b," ");c=b[4]
        if(b[1]=="chain"&&c~/^(cf_fwd|cf_input|cf_dns)$/){
            n=split(now[k],a,"\n");good=1;guard=0;target=0
            for(i=1;i<=n;i++){if(a[i]=="")continue;split(a[i],r," ");if(r[5]=="-N")continue
                body=a[i];sub(/^RULE [^ ]+ [^ ]+ [^ ]+ /,"",body)
                # Normalization sorts complete fragments: these have only comment/module/jump.
                want="-A " c " --comment cf:v2 -j cf2_" slot "_g -m comment"
                if(c=="cf_fwd"&&body==want&&target==0&&++guard==1)continue
                if((index(old[k],a[i] "\n")||index(new[k],a[i] "\n"))&&++target==1)continue
                good=0
            }if(good&&target<=1)continue
        }
        if(phase=="staging"&&!reachable&&new[k]!=""&&index(new[k],now[k])==1)continue
        if(phase=="cleanup"&&b[1]=="chain"&&now[k]=="RULE " b[2] " " b[3] " " b[4] " -N " b[4] "\n")continue
        exit 1
    }
    # A wholly absent owned kernel can be rebuilt as degraded restoration.
    # Partial loss of a prepared generation or its sets must remain fenced.
    if(rules&&phase!="staging"&&phase!="cleanup"&&phase!="rebase_ready")for(k in new){split(k,b," ");if((b[1]=="chain"&&b[4]~("^cf2_" slot "_[figd]$")||b[1]=="set"&&b[2]~("^cf2_" slot "_(k|p|d4|d6|u)$"))&&!(k in now))exit 1}
    }' || { cf_fail transition_object_drift;return 1; }
    cf_reference_guard_v2
}
cf_reference_guard_v2() {
    cf_rg_allowed=
    if [ -n "${CF_TRANSITION-}" ];then
        cf_rg_allowed=$(printf '%s\n' "$CF_TRANSITION" | awk '/^(BEFORE|AFTER|REPAIRED|REPAIR_BEFORE) RULE /{sub(/^[^ ]+ RULE [^ ]+ [^ ]+ [^ ]+ /,"");print}')
    elif cf_safe_file "$CF_RUNTIME/firewall.snapshot";then
        cf_rg_allowed=$(awk '/^RULE /{sub(/^RULE [^ ]+ [^ ]+ [^ ]+ /,"");print}' "$CF_RUNTIME/firewall.snapshot")
    fi
    for cf_rg_f in 4 6;do
        for cf_rg_t in filter nat mangle raw;do
            cf_rg_lines=$(cf_table "$cf_rg_f" -t "$cf_rg_t" -S) || { cf_fail reference_inspection_failed;return 1; }
            printf '%s\n' "$cf_rg_lines" | cf_normal_rules | awk -v allowed="$cf_rg_allowed" -v slot="$CF_SLOT" -v t="$cf_rg_t" -v f="$cf_rg_f" '
            BEGIN{n=split(allowed,a,"\n");for(i=1;i<=n;i++)ok[a[i]]=1}
            $1=="-A"{owned=($2~/^(cf_fwd|cf_input|cf_dns|cf2_[ab]_[figd])$/)
                ref=0;for(i=3;i<NF;i++)if(($i=="-j"||$i=="-g")&&$(i+1)~/^(cf_fwd|cf_input|cf_dns|cf2_[ab]_[figd])$/||$i=="--match-set"&&$(i+1)~/^cf2_[ab]_(k|p|d4|d6|u)$/)ref=1
                if(!ref)next
                if(owned&&ok[$0])next
                if(t=="filter"&&$2=="cf_fwd"&&$0=="-A cf_fwd --comment cf:v2 -j cf2_" slot "_g -m comment")next
                if(t=="filter"&&$2=="forwarding_rule"&&$0=="-A forwarding_rule --comment cf:v1 -j cf_fwd -m comment")next
                if(t=="filter"&&$2=="input_rule"&&$0=="-A input_rule --comment cf:v1 -i br-lan -j cf_input -m comment")next
                if(t=="nat"&&f==4&&$2=="prerouting_rule"&&$0=="-A prerouting_rule --comment cf:v1 -i br-lan -j cf_dns -m comment")next
                exit 1
            }' || { cf_fail foreign_object_reference;return 1; }
        done
    done
    cf_rg_sets=$(cf_backend ipset save) || return 1
    printf '%s\n' "$cf_rg_sets" | awk '$1=="add"&&$3~/^cf2_[ab]_(k|p|d4|d6|u)$/{exit 1}' || { cf_fail foreign_set_reference;return 1; }
}
cf_preflight() {
    cf_slot_load
    if [ -e "$CF_RUNTIME/firewall.preflight" ] || [ -L "$CF_RUNTIME/firewall.preflight" ];then
        [ "${CF_INSTALL_AUTH:-0}" = 1 ] && [ "${cf_action-}" = apply-fw ] || { cf_fail preflight_baseline_requires_installer;return 1; }
        cf_preflight_baseline_verify || return 1
    fi
    for cf_dep in iptables ip6tables ipset uci conntrack ip fw3 sync;do cf_backend_available "$cf_dep" || { cf_fail missing_dependencies;return 1; };done
    cf_network || return 1
    for cf_pf_f in 4 6;do
        cf_parent_order "$cf_pf_f" filter FORWARD forwarding_rule && cf_parent_order "$cf_pf_f" filter INPUT input_rule || return 1
    done
    cf_parent_order 4 nat PREROUTING prerouting_rule || return 1
    if ! cf_ownership_valid;then
        [ ! -e "$CF_RUNTIME/firewall.owned" ] && [ ! -L "$CF_RUNTIME/firewall.owned" ] || { cf_fail unsafe_ownership_record;return 1; }
        cf_pf_inventory=$(cf_snapshot) || return 1
        [ -z "$(printf '%s\n' "$cf_pf_inventory" | awk '$1!="SCHEDULE"{print}')" ] || { cf_fail foreign_chain_collision;return 1; }
        for cf_pf_set in cf_kids cf_paused cf_doh cf_doh6;do if cf_backend ipset save "$cf_pf_set" >/dev/null 2>&1;then cf_fail v1_reinstall_required;return 1;fi;done
    fi
    cf_uci_pending=$(cf_backend uci -q changes firewall) || { cf_fail uci_inspection_failed;return 1; }
    [ -z "$cf_uci_pending" ] || { cf_fail foreign_uci_pending_changes;return 1; }
    cf_uci_existing=$(cf_backend uci -q show firewall) || return 1
    cf_uci_sections=$(printf '%s\n' "$cf_uci_existing" | awk -F '[.=]' '$1=="firewall"&&$2~/^cf_sched_/&&NF==3{print $2}' | sort -u)
    for cf_section in $cf_uci_sections;do
        cf_meta=$(cf_backend uci -q get "firewall.$cf_section.couvrefeu_owner") || { cf_fail foreign_schedule_collision;return 1; }
        [ "$cf_meta" = v1 ] && cf_ownership_valid || { cf_fail foreign_schedule_collision;return 1; }
    done
    if [ -e "$CF_RUNTIME/firewall.intent" ];then
        cf_transition_read && cf_transition_inventory_check || return 1
        cf_ab_new=$(printf '%s\n' "$CF_TRANSITION" | awk '$1=="NEW"{print $2}')
        cf_ab_old=$(printf '%s\n' "$CF_TRANSITION" | awk '$1=="OLD"{print $2}')
        cf_ab_phase=$(printf '%s\n' "$CF_TRANSITION" | awk '$1=="PHASE"{print $2}')
        if [ "$cf_ab_new" != "${CF_OLD_DIGEST:-$CF_DIGEST}" ];then
            [ "$cf_ab_old" = "${CF_OLD_DIGEST:-$CF_DIGEST}" ] || { cf_fail transition_state_mismatch;return 1; }
            case $cf_ab_phase in staging|staged)cf_slot_delete "$CF_SLOT" || return 1;rm -f "$CF_RUNTIME/firewall.intent" || return 1;CF_TRANSITION=;cf_slot_load;;*)cf_fail transition_state_mismatch;return 1;;esac
        fi
    fi
    cf_address_refresh || return 1
    case ${cf_action-} in pause|sync|rpc-sync)[ "$CF_ADDRESS_OK" = true ] || { cf_fail incomplete_address_coverage;return 1; };;esac
    cf_reference_guard_v2
}
cf_transition_identity() {
    cf_ti_save=$CF_POLICY
    CF_POLICY=$(printf '%s\n%s\n' "${CF_OLD_POLICY-}" "$CF_POLICY" | awk -F '\t' '$1=="P"&&$3!="-"{print}' | sort -u)
    cf_policy_safe && cf_ssh_guard || { CF_POLICY=$cf_ti_save;return 1; }
    CF_UNION=$(cf_kids)
    CF_UNION_ADDRESSES=$(cf_addresses) || { CF_POLICY=$cf_ti_save;return 1; }
    CF_POLICY=$cf_ti_save
    cf_ti_required=$CF_UNION
    case ${cf_action-} in expire|resume|apply-fw)cf_ti_required=$(cf_effective_blocked_macs) || return 1;;esac
    printf '%s\n' "$CF_UNION_ADDRESSES" | awk -F '\t' -v macs="$cf_ti_required" 'BEGIN{n=split(macs,a,"\n");for(i=1;i<=n;i++)if(a[i]!="")need[a[i]]=1}NF==2&&($2 in need){have[$2]=1}$1=="UNCERTAIN"&&($3 in need){bad=1}END{for(m in need)if(!have[m])bad=1;exit bad}' || { cf_fail incomplete_transition_address_coverage;return 1; }
    CF_PROTECTION_DIGEST=$(sha256sum "$CF_PROTECTED" | awk '{print $1}')
}
cf_transition_fresh() {
    cf_tf_saved=$CF_POLICY
    CF_POLICY=$(printf '%s\n' "$CF_UNION" | awk 'NF{print "P\ttransition\t" $0}')
    cf_policy_safe || { CF_POLICY=$cf_tf_saved;return 1; }
    cf_tf_observed=$(cf_addresses) || { CF_POLICY=$cf_tf_saved;return 1; }
    CF_POLICY=$cf_tf_saved
    cf_tf_recorded=$(printf '%s\n' "$CF_TRANSITION" | awk '/^ADDRESS /{sub(/^ADDRESS /,"");print}')
    if [ "$cf_tf_observed" != "$cf_tf_recorded" ];then
        [ -z "$(cf_effective_blocked_macs)" ] && [ "${CF_CONSERVATIVE_RECOVERY:-0}" != 1 ] || { cf_fail transition_address_changed;return 1; }
        cf_transition_repair_evidence "$cf_tf_observed" || return 1
    fi
    cf_tf_protection=$(printf '%s\n' "$CF_TRANSITION" | awk '$1=="PROTECTION"{print $2}')
    [ "$cf_tf_protection" = "$(sha256sum "$CF_PROTECTED" | awk '{print $1}')" ] || { cf_fail transition_protection_changed;return 1; }
}
cf_transition_repair_evidence() {
    cf_te_fresh=$1
    cf_te_current=$(cf_snapshot) || return 1
    cf_te_unsafe=$(printf '%s\n' "$cf_te_current" | awk -v fresh="$cf_te_fresh" -v kids="$CF_UNION" '
    BEGIN{n=split(kids,a,"\n");for(i=1;i<=n;i++)m[a[i]]=1;n=split(fresh,a,"\n");for(i=1;i<=n;i++){split(a[i],b,"\t");if(b[2] in m)safe[b[1]]=1}}
    $1=="RULE"&&$4~/^cf2_[ab]_[fg]$/&&$5=="-A"{ip="";reverse=0;blocked=0;for(i=7;i<NF;i++){if($i=="-d")ip=$(i+1);if($i=="-o"&&$(i+1)=="br-lan")reverse=1;if($i=="-j"&&$(i+1)~/^(REJECT|DROP)$/)blocked=1}if(reverse&&blocked&&ip!=""&&!safe[ip])print}')
    cf_te_plan=$(printf '%s\n' "$cf_te_unsafe" | awk '{f=$2;t=$3;c=$4;sub(/^RULE [^ ]+ [^ ]+ [^ ]+ -A [^ ]+ /,"");print f "\t" t "\t" c "\t" $0}')
    # Persist exact before/after one-effect witnesses before removing unsafe
    # selectors. Recovery never repopulates them from an obsolete old plan.
    cf_te_records=$(printf '%s\n' "$CF_TRANSITION" | awk -v unsafe="$cf_te_unsafe" '
    BEGIN{n=split(unsafe,a,"\n");for(i=1;i<=n;i++)drop[a[i]]=1}
    $1=="ADDRESS"||$1=="REPAIR"||$1=="REPAIR_BEFORE"{next}
    $1=="AFTER"{line=$0;sub(/^AFTER /,"",line);if(drop[line])next}
    {print}')
    cf_te_plan_new=$(printf '%s\n' "$CF_EXPECTED" | while IFS="$(printf '\t')" read -r cf_te_f cf_te_t cf_te_c cf_te_rule;do
        [ -n "$cf_te_f" ] || continue
        cf_te_key=$(cf_inventory_plan "$(printf '%s\t%s\t%s\t%s' "$cf_te_f" "$cf_te_t" "$cf_te_c" "$cf_te_rule")" | awk '$5=="-A"{print}')
        if ! printf '%s\n' "$cf_te_unsafe" | awk -v k="$cf_te_key" '$0==k{yes=1}END{exit !yes}';then printf '%s\t%s\t%s\t%s\n' "$cf_te_f" "$cf_te_t" "$cf_te_c" "$cf_te_rule";fi
    done)
    cf_te_guard_new=$(printf '%s\n' "$CF_GUARD_PLAN" | while IFS="$(printf '\t')" read -r cf_te_f cf_te_t cf_te_c cf_te_rule;do
        [ -n "$cf_te_f" ] || continue
        cf_te_key=$(cf_inventory_plan "$(printf '%s\t%s\t%s\t%s' "$cf_te_f" "$cf_te_t" "$cf_te_c" "$cf_te_rule")" | awk '$5=="-A"{print}')
        if ! printf '%s\n' "$cf_te_unsafe" | awk -v k="$cf_te_key" '$0==k{yes=1}END{exit !yes}';then printf '%s\t%s\t%s\t%s\n' "$cf_te_f" "$cf_te_t" "$cf_te_c" "$cf_te_rule";fi
    done)
    CF_TRANSITION="$(printf '%s\n' "$cf_te_records" | awk '$1!="PLAN"&&$1!="GUARD"{print}')
$(printf '%s\n' "$cf_te_current" | awk 'NF{print "REPAIR_BEFORE " $0}')
$(printf '%s\n' "$cf_te_fresh" | awk 'NF{print "ADDRESS " $0}')
$(printf '%s\n' "$cf_te_plan" | awk 'NF{print "REPAIR\t" $0}')
$(printf '%s\n' "$cf_te_plan_new" | awk 'NF{print "PLAN\t" $0}')
$(printf '%s\n' "$cf_te_guard_new" | awk 'NF{print "GUARD\t" $0}')"
    CF_EXPECTED=$cf_te_plan_new;CF_GUARD_PLAN=$cf_te_guard_new
    CF_UNION_ADDRESSES=$cf_te_fresh
    cf_durable_record firewall.intent "$CF_TRANSITION" && cf_stale_repair
}
cf_stale_plan() {
    CF_REPAIR=$(printf '%s\n' "$CF_BEFORE" | awk -v fresh="$CF_UNION_ADDRESSES" -v kids="$CF_UNION" '
    BEGIN{n=split(kids,a,"\n");for(i=1;i<=n;i++)m[a[i]]=1;n=split(fresh,a,"\n");for(i=1;i<=n;i++){split(a[i],b,"\t");if(b[2] in m)safe[b[1]]=1}}
    $1=="RULE"&&$4~/^cf2_[ab]_f$/&&$5=="-A"{ip="";reverse=0;reject=0;for(i=7;i<NF;i++){if($i=="-d")ip=$(i+1);if($i=="-o"&&$(i+1)=="br-lan")reverse=1;if($i=="-j"&&$(i+1)=="REJECT")reject=1}if(reverse&&reject&&ip!=""&&!safe[ip]){f=$2;t=$3;c=$4;sub(/^RULE [^ ]+ [^ ]+ [^ ]+ -A [^ ]+ /,"");print f "\t" t "\t" c "\t" $0}}')
    cf_sp_removed=$(cf_inventory_plan "$CF_REPAIR" | awk '$5=="-A"{print}')
    CF_REPAIRED=$(printf '%s\n' "$CF_BEFORE" | awk -v removed="$cf_sp_removed" 'BEGIN{n=split(removed,a,"\n");for(i=1;i<=n;i++)drop[a[i]]=1}!drop[$0]{print}')
}
cf_stale_repair() {
    cf_sr_plan=$(printf '%s\n' "$CF_TRANSITION" | awk '/^REPAIR\t/{sub(/^REPAIR\t/,"");print}')
    while IFS="$(printf '\t')" read -r cf_sr_f cf_sr_t cf_sr_c cf_sr_rule;do
        [ -n "$cf_sr_f" ] || continue
        cf_sr_rows=$(cf_dispatch_rules "$cf_sr_f" "$cf_sr_t" "$cf_sr_c") || return 1
        cf_sr_exact=$(printf '%s\n' "-A $cf_sr_c $cf_sr_rule" | cf_normal_rules)
        if printf '%s\n' "$cf_sr_rows" | awk -v exact="$cf_sr_exact" '$0==exact{yes=1}END{exit !yes}';then
            cf_transition_inventory_check || return 1
            cf_sr_before=$(cf_snapshot) || return 1
            cf_sr_remove=$(cf_inventory_plan "$(printf '%s\t%s\t%s\t%s' "$cf_sr_f" "$cf_sr_t" "$cf_sr_c" "$cf_sr_rule")" | awk '$5=="-A"{print}')
            cf_sr_after=$(printf '%s\n' "$cf_sr_before" | awk -v remove="$cf_sr_remove" '$0!=remove{print}')
            CF_TRANSITION=$(printf '%s\n' "$CF_TRANSITION" | awk '$1!="REPAIR_BEFORE"&&$1!="REPAIRED"{print}')
            CF_TRANSITION="$CF_TRANSITION
$(printf '%s\n' "$cf_sr_before" | awk 'NF{print "REPAIR_BEFORE " $0}')
$(printf '%s\n' "$cf_sr_after" | awk 'NF{print "REPAIRED " $0}')"
            cf_durable_record firewall.intent "$CF_TRANSITION" || return 1
            set -- $cf_sr_rule
            cf_table "$cf_sr_f" -t "$cf_sr_t" -D "$cf_sr_c" "$@" || { cf_fail stale_selector_repair_failed;return 1; }
        fi
    done <<EOR
$cf_sr_plan
EOR
}
cf_guard_plan() {
    for cf_gp_f in 4 6;do
        while IFS= read -r cf_gp_mac;do printf '%s\tfilter\tcf2_%s_g\t-i br-lan -m mac --mac-source %s -m comment --comment cf:v2 -j RETURN\n' "$cf_gp_f" "$CF_SLOT" "$cf_gp_mac";done < "$CF_PROTECTED"
        printf '%s\n' "$CF_UNION_ADDRESSES" | awk -F '\t' -v f="$cf_gp_f" -v s="$CF_SLOT" '$1=="PROTECTED"&&((index($2,":")>0)==(f==6)){printf "%s\tfilter\tcf2_%s_g\t-o br-lan -d %s -m comment --comment cf:v2 -j RETURN\n",f,s,$2}'
        printf '%s\tfilter\tcf2_%s_g\t-i br-lan -m set --match-set cf2_%s_u src -m comment --comment cf:v2 -j DROP\n' "$cf_gp_f" "$CF_SLOT" "$CF_SLOT"
        printf '%s\n' "$CF_UNION_ADDRESSES" | awk -F '\t' -v f="$cf_gp_f" -v s="$CF_SLOT" -v macs="$CF_UNION" 'BEGIN{n=split(macs,a,"\n");for(i=1;i<=n;i++)m[a[i]]=1}NF==2&&m[$2]&&((index($1,":")>0)==(f==6)){printf "%s\tfilter\tcf2_%s_g\t-o br-lan -d %s -m comment --comment cf:v2 -j DROP\n",f,s,$1}'
        printf '%s\tfilter\tcf2_%s_g\t-m comment --comment cf:v2 -j RETURN\n' "$cf_gp_f" "$CF_SLOT"
    done
}
cf_build_plan() {
    cf_bp_plan=$1
    while IFS="$(printf '\t')" read -r cf_bp_f cf_bp_t cf_bp_c;do
        [ -n "$cf_bp_f" ] || continue
        if ! cf_table "$cf_bp_f" -t "$cf_bp_t" -S "$cf_bp_c" >/dev/null 2>&1;then cf_table "$cf_bp_f" -t "$cf_bp_t" -N "$cf_bp_c" || return 1;fi
        cf_bp_actual=$(cf_dispatch_rules "$cf_bp_f" "$cf_bp_t" "$cf_bp_c") || return 1
        cf_bp_desired=$(printf '%s\n' "$cf_bp_plan" | awk -F '\t' -v f="$cf_bp_f" -v t="$cf_bp_t" -v c="$cf_bp_c" '$1==f&&$2==t&&$3==c{print "-A " c " " $4}' | cf_normal_rules)
        # Resume only an exact recorded ordered prefix; never flush a chain.
        printf '%s\n' "$cf_bp_actual" | awk -v expected="$cf_bp_desired" 'BEGIN{n=split(expected,a,"\n")}NF{if($0!=a[++i])exit 1}' || { cf_fail staged_chain_drift;return 1; }
        cf_bp_count=$(printf '%s\n' "$cf_bp_actual" | awk 'NF{n++}END{print n+0}')
        cf_bp_missing=$(printf '%s\n' "$cf_bp_plan" | awk -F '\t' -v f="$cf_bp_f" -v t="$cf_bp_t" -v c="$cf_bp_c" -v n="$cf_bp_count" '$1==f&&$2==t&&$3==c{if(++i>n)print $4}')
        while IFS= read -r cf_bp_add;do
            [ -n "$cf_bp_add" ] || continue
            set -- $cf_bp_add
            cf_table "$cf_bp_f" -t "$cf_bp_t" -A "$cf_bp_c" "$@" || { cf_fail rule_apply_failed;return 1; }
        done <<EOR
$cf_bp_missing
EOR
    done <<EOP
$(printf '%s\n' "$cf_bp_plan" | awk -F '\t' 'NF==4&&!seen[$1 FS $2 FS $3]++{print $1 FS $2 FS $3}')
EOP
}
cf_build_sets() {
    for cf_bs_suffix in k p d4 d6 u;do
        cf_bs_name=cf2_${CF_SLOT}_$cf_bs_suffix
        case $cf_bs_suffix in k|p|u)cf_bs_type=hash:mac;cf_bs_family=inet;;d4)cf_bs_type=hash:ip;cf_bs_family=inet;;d6)cf_bs_type=hash:ip;cf_bs_family=inet6;;esac
        if ! cf_backend ipset save "$cf_bs_name" >/dev/null 2>&1;then
            if [ "$cf_bs_type" = hash:ip ];then cf_backend ipset create "$cf_bs_name" "$cf_bs_type" family "$cf_bs_family" || return 1;else cf_backend ipset create "$cf_bs_name" "$cf_bs_type" || return 1;fi
        fi
        cf_bs_members=$(printf '%s\n' "$CF_TRANSITION" | awk -v s="$cf_bs_name" '$1=="AFTER"&&$2=="SET"&&$3==s{print $4}')
        for cf_bs_m in $cf_bs_members;do cf_backend ipset add "$cf_bs_name" "$cf_bs_m" -exist || return 1;done
    done
}
cf_transition_prepare() {
    platform_deadline_check
    cf_slot_load
    CF_EXPECTED=$(cf_plan) || return 1
    if [ ! -e "$CF_RUNTIME/firewall.intent" ] && [ ! -e "$CF_RUNTIME/error" ] && cf_safe_file "$CF_RUNTIME/confirmed" && cf_ownership_valid && cf_verify;then
        CF_TRANSITION=;CF_PREPARED_NOOP=1;return 0
    fi
    CF_ERROR=
    if [ -e "$CF_RUNTIME/firewall.intent" ] && [ "${CF_REBASE_READY:-0}" != 1 ];then
        cf_transition_read && cf_transition_inventory_check || return 1
        cf_tp_new=$(printf '%s\n' "$CF_TRANSITION" | awk '$1=="NEW"{print $2}')
        cf_tp_desired=$(printf '%s\n' "$CF_POLICY" | sha256sum | awk '{print $1}')
        [ "$cf_tp_new" = "$cf_tp_desired" ] || { cf_fail firewall_transition_incomplete;return 1; }
        return 0
    fi
    CF_BEFORE=$(cf_snapshot) || return 1
    if cf_safe_file "$CF_RUNTIME/firewall.snapshot";then
        cf_tp_saved=$(awk '{print}' "$CF_RUNTIME/firewall.snapshot")
        cf_tp_now=$(printf '%s\n' "$CF_BEFORE" | awk '$1!="SCHEDULE"{print}')
        cf_tp_old=$(printf '%s\n' "$cf_tp_saved" | awk '$1!="SCHEDULE"{print}')
        # A complete absent kernel is degraded restoration, never continuity evidence.
        [ "$cf_tp_now" = "$cf_tp_old" ] || printf '%s\n' "$cf_tp_now" | awk -v known="$cf_tp_old" 'BEGIN{n=split(known,a,"\n");for(i=1;i<=n;i++)ok[a[i]]=1}NF&&!ok[$0]{exit 1}' || { cf_fail owned_rule_drift;return 1; }
    fi
    cf_transition_identity || return 1
    if cf_ownership_valid;then if [ "$CF_SLOT" = a ];then CF_SLOT=b;else CF_SLOT=a;fi;fi
    CF_ADDRESS_DATA=$CF_UNION_ADDRESSES
    cf_stale_plan || return 1
    CF_EXPECTED=$(cf_plan) || return 1
    CF_GUARD_PLAN=$(cf_guard_plan) || return 1
    CF_AFTER=$(cf_inventory_plan "$CF_EXPECTED
$CF_GUARD_PLAN
$(cf_dispatch_plan "$CF_SLOT")") || return 1
    for cf_tp_suffix in k p d4 d6 u;do
        cf_tp_name=cf2_${CF_SLOT}_$cf_tp_suffix
        case $cf_tp_suffix in k)cf_tp_m=$(cf_kids);cf_tp_type=hash:mac;cf_tp_family=inet;;p)cf_tp_m=$(cf_effective_macs);cf_tp_type=hash:mac;cf_tp_family=inet;;u)cf_tp_m=$CF_UNION;cf_tp_type=hash:mac;cf_tp_family=inet;;d4)cf_tp_m=$(cf_desired_set cf_doh);cf_tp_type=hash:ip;cf_tp_family=inet;;d6)cf_tp_m=$(cf_desired_set cf_doh6);cf_tp_type=hash:ip;cf_tp_family=inet6;;esac
        CF_AFTER="$CF_AFTER
SETDEF $cf_tp_name $cf_tp_type $cf_tp_family
$(printf '%s\n' "$cf_tp_m" | awk -v s="$cf_tp_name" 'NF{print "SET " s " " $0}')"
    done
    CF_TRANSITION="TRANSITION 2
SLOT $CF_SLOT
OLD ${CF_OLD_DIGEST:-$CF_DIGEST}
NEW $(printf '%s\n' "$CF_POLICY" | sha256sum | awk '{print $1}')
GENERATION ${CF_GENERATION:--}
RECEIPT ${CF_REQUEST_ID:--}
OLD_RECEIPT ${CF_CURRENT:--}
EPOCH $CF_EXPIRY_NOW
NATIVE_OLD $(if cf_safe_file "$CF_RUNTIME/firewall.snapshot";then awk '/^SCHEDULE /{sub(/^SCHEDULE /,"");print}' "$CF_RUNTIME/firewall.snapshot";fi | sha256sum | awk '{print $1}')
NATIVE_NEW $(cf_schedule_specs | sha256sum | awk '{print $1}')
BOOT $(cf_boot_id)
PHASE staging
PROTECTION $CF_PROTECTION_DIGEST
$(printf '%s\n' "$CF_UNION" | awk 'NF{print "UNION " $0}')
$(printf '%s\n' "$CF_UNION_ADDRESSES" | awk 'NF{print "ADDRESS " $0}')
$(printf '%s\n' "$CF_EXPECTED" | awk 'NF{print "PLAN\t" $0}')
$(printf '%s\n' "$CF_GUARD_PLAN" | awk 'NF{print "GUARD\t" $0}')
$(printf '%s\n' "$CF_BEFORE" | awk 'NF{print "BEFORE " $0}')
$(printf '%s\n' "$CF_REPAIRED" | awk 'NF{print "REPAIRED " $0}')
$(printf '%s\n' "$CF_REPAIR" | awk 'NF{print "REPAIR\t" $0}')
$(printf '%s\n' "$CF_AFTER" | awk 'NF{print "AFTER " $0}')"
    cf_durable_record firewall.intent "$CF_TRANSITION" || return 1
    cf_rpc_checkpoint after_initial_intent
    if ! cf_ownership_valid;then cf_durable_record firewall.owned "couvrefeu-owned-v2
$CF_SLOT" || return 1;fi
    cf_stale_repair && cf_build_sets && cf_build_plan "$CF_EXPECTED
$CF_GUARD_PLAN" && cf_transition_inventory_check || return 1
    cf_transition_phase staged
}
cf_dispatch_rules() {
    cf_dispatch_raw=$(cf_table "$1" -t "$2" -S "$3") || return 1
    printf '%s\n' "$cf_dispatch_raw" | cf_normal_rules | awk '$1=="-A"{print}'
}
cf_dispatch_replace() {
    cf_dx_f=$1;cf_dx_t=$2;cf_dx_c=$3;cf_dx_target=$4;cf_dx_pos=$5
    cf_dx_now=$(cf_dispatch_rules "$cf_dx_f" "$cf_dx_t" "$cf_dx_c") || return 1
    cf_dx_want=$(printf '%s\n' "-A $cf_dx_c -m comment --comment cf:v2 -j $cf_dx_target" | cf_normal_rules)
    cf_dx_line=$(printf '%s\n' "$cf_dx_now" | awk -v n="$cf_dx_pos" 'NR==n{print}')
    [ "$cf_dx_line" = "$cf_dx_want" ] && return 0
    printf '%s\n' "$cf_dx_line" | awk -v c="$cf_dx_c" '$0=="-A " c " --comment cf:v2 -j cf2_a_f -m comment"||$0=="-A " c " --comment cf:v2 -j cf2_b_f -m comment"||$0=="-A " c " --comment cf:v2 -j cf2_a_i -m comment"||$0=="-A " c " --comment cf:v2 -j cf2_b_i -m comment"||$0=="-A " c " --comment cf:v2 -j cf2_a_d -m comment"||$0=="-A " c " --comment cf:v2 -j cf2_b_d -m comment"{yes=1}END{exit !yes}' || { cf_fail dispatcher_drift;return 1; }
    cf_transition_phase "switch_${cf_dx_f}_${cf_dx_c}" || return 1
    cf_table "$cf_dx_f" -t "$cf_dx_t" -R "$cf_dx_c" "$cf_dx_pos" -m comment --comment cf:v2 -j "$cf_dx_target" || { cf_fail dispatcher_switch_failed;return 1; }
}
cf_hook() {
    cf_h_f=$1;cf_h_t=$2;cf_h_p=$3;cf_h_c=$4
    cf_h_lines=$(cf_table "$cf_h_f" -t "$cf_h_t" -S "$cf_h_p") || return 1
    cf_h_exact=$(printf '%s\n' "-A $cf_h_p $(cf_hook_args "$cf_h_c") -j $cf_h_c" | cf_normal_rules)
    cf_h_first=$(printf '%s\n' "$cf_h_lines" | cf_normal_rules | awk '$1=="-A"{print;exit}')
    [ "$cf_h_first" = "$cf_h_exact" ] && return 0
    printf '%s\n' "$cf_h_lines" | awk -v c="$cf_h_c" '{for(i=1;i<NF;i++)if(($i=="-j"||$i=="-g")&&$(i+1)==c)exit 1}' || { cf_fail hook_drift;return 1; }
    set -- $(cf_hook_args "$cf_h_c")
    cf_table "$cf_h_f" -t "$cf_h_t" -I "$cf_h_p" 1 "$@" -j "$cf_h_c"
}
cf_dispatch_initial() {
    while IFS="$(printf '\t')" read -r cf_di_f cf_di_t cf_di_c cf_di_rule;do
        cf_di_all=$(cf_table "$cf_di_f" -t "$cf_di_t" -S) || return 1
        if ! printf '%s\n' "$cf_di_all" | awk -v c="$cf_di_c" '$1=="-N"&&$2==c{yes=1}END{exit !yes}';then cf_table "$cf_di_f" -t "$cf_di_t" -N "$cf_di_c" || return 1;fi
        cf_di_rows=$(cf_dispatch_rules "$cf_di_f" "$cf_di_t" "$cf_di_c") || return 1
        if [ -z "$cf_di_rows" ];then set -- $cf_di_rule;cf_table "$cf_di_f" -t "$cf_di_t" -A "$cf_di_c" "$@" || return 1;fi
    done <<EOD
$(cf_dispatch_plan "$CF_SLOT")
EOD
    for cf_di_f in 4 6;do cf_hook "$cf_di_f" filter forwarding_rule cf_fwd && cf_hook "$cf_di_f" filter input_rule cf_input || return 1;done
    cf_hook 4 nat prerouting_rule cf_dns
}
cf_guard_attach() {
    for cf_ga_f in 4 6;do
        cf_ga_rules=$(cf_dispatch_rules "$cf_ga_f" filter cf_fwd) || return 1
        cf_ga_exact=$(printf '%s\n' "-A cf_fwd -m comment --comment cf:v2 -j cf2_${CF_SLOT}_g" | cf_normal_rules)
        if [ "$(printf '%s\n' "$cf_ga_rules" | awk 'NR==1{print}')" != "$cf_ga_exact" ];then
            [ "$(printf '%s\n' "$cf_ga_rules" | awk 'NF{n++}END{print n+0}')" = 1 ] || { cf_fail dispatcher_drift;return 1; }
            cf_transition_phase "guard_$cf_ga_f" || return 1
            cf_table "$cf_ga_f" -t filter -I cf_fwd 1 -m comment --comment cf:v2 -j "cf2_${CF_SLOT}_g" || { cf_fail guard_attach_failed;return 1; }
        fi
    done
    CF_GUARDED=1
}
cf_guard_verify() {
    for cf_gv_f in 4 6;do
        cf_gv_rows=$(cf_dispatch_rules "$cf_gv_f" filter cf_fwd) || return 1
        [ "$(printf '%s\n' "$cf_gv_rows" | awk 'NR==1{print}')" = "$(printf '%s\n' "-A cf_fwd -m comment --comment cf:v2 -j cf2_${CF_SLOT}_g" | cf_normal_rules)" ] || { cf_fail guard_missing;return 1; }
        cf_gv_actual=$(cf_dispatch_rules "$cf_gv_f" filter "cf2_${CF_SLOT}_g") || { cf_fail guard_missing;return 1; }
        cf_gv_expected=$(printf '%s\n' "$CF_GUARD_PLAN" | awk -F '\t' -v f="$cf_gv_f" '$1==f{print "-A " $3 " " $4}' | cf_normal_rules)
        [ -n "$cf_gv_expected" ] && [ "$cf_gv_actual" = "$cf_gv_expected" ] || { cf_fail guard_body_drift;return 1; }
    done
    cf_gv_union=$(cf_backend ipset save "cf2_${CF_SLOT}_u") || { cf_fail guard_set_missing;return 1; }
    printf '%s\n' "$cf_gv_union" | awk -v s="cf2_${CF_SLOT}_u" '$1=="create"&&$2==s&&$3=="hash:mac"{f="inet";for(i=4;i<NF;i++)if($i=="family")f=$(i+1);if(f=="inet")yes=1}END{exit !yes}' || { cf_fail guard_set_type_drift;return 1; }
    cf_gv_members=$(cf_set_members "cf2_${CF_SLOT}_u") || return 1
    [ "$cf_gv_members" = "$(printf '%s\n' "$CF_UNION" | awk 'NF' | sort -u)" ] || { cf_fail guard_set_drift;return 1; }
    cf_transition_inventory_check
}
cf_slot_delete() {
    cf_sd_slot=$1
    cf_reference_guard_v2 || return 1
    while read -r cf_sd_f cf_sd_t cf_sd_c;do
        cf_sd_all=$(cf_table "$cf_sd_f" -t "$cf_sd_t" -S) || return 1
        if ! printf '%s\n' "$cf_sd_all" | awk -v c="$cf_sd_c" '$1=="-N"&&$2==c{yes=1}END{exit !yes}';then continue;fi
        # Do not flush a referenced object even if the eventual -X would refuse.
        printf '%s\n' "$cf_sd_all" | awk -v c="$cf_sd_c" '{for(i=1;i<NF;i++)if(($i=="-j"||$i=="-g")&&$(i+1)==c)exit 1}' || { cf_fail referenced_generation;return 1; }
        cf_table "$cf_sd_f" -t "$cf_sd_t" -F "$cf_sd_c" && cf_table "$cf_sd_f" -t "$cf_sd_t" -X "$cf_sd_c" || return 1
    done <<EOS
$(cf_slot_chains "$cf_sd_slot")
EOS
    for cf_sd_set in $(cf_slot_sets "$cf_sd_slot");do if cf_backend ipset save "$cf_sd_set" >/dev/null 2>&1;then cf_backend ipset destroy "$cf_sd_set" || return 1;fi;done
}
cf_guard_delete() {
    for cf_gd_f in 4 6;do
        cf_gd_all=$(cf_table "$cf_gd_f" -t filter -S) || return 1
        if printf '%s\n' "$cf_gd_all" | awk -v c="cf2_${CF_SLOT}_g" '$1=="-N"&&$2==c{yes=1}END{exit !yes}';then
            printf '%s\n' "$cf_gd_all" | awk -v c="cf2_${CF_SLOT}_g" '{for(i=1;i<NF;i++)if(($i=="-j"||$i=="-g")&&$(i+1)==c)exit 1}' || return 1
            cf_table "$cf_gd_f" -t filter -F "cf2_${CF_SLOT}_g" && cf_table "$cf_gd_f" -t filter -X "cf2_${CF_SLOT}_g" || return 1
        fi
    done
    if cf_backend ipset save "cf2_${CF_SLOT}_u" >/dev/null 2>&1;then cf_backend ipset destroy "cf2_${CF_SLOT}_u" || return 1;fi
}
cf_transition_rebase() {
    CF_REBASE_COUNT=$((${CF_REBASE_COUNT:-0} + 1))
    [ "$CF_REBASE_COUNT" -le 1 ] || { cf_fail transition_evidence_expired;return 1; }
    cf_rb_phase=$(printf '%s\n' "$CF_TRANSITION" | awk '$1=="PHASE"{print $2}')
    if [ "$cf_rb_phase" != rebase_ready ];then
        CF_PREPARED_EPOCH=$(printf '%s\n' "$CF_TRANSITION" | awk '$1=="EPOCH"{print $2}')
        cf_number_valid "$CF_PREPARED_EPOCH" || { cf_fail unsafe_transition;return 1; }
        CF_CONSERVATIVE_RECOVERY=1
        cf_apply
        cf_rb_result=$?
        unset CF_PREPARED_EPOCH CF_CONSERVATIVE_RECOVERY
        [ "$cf_rb_result" = 0 ] || return "$cf_rb_result"
    fi
    # The conservative complete generation has a durable exact runtime snapshot,
    # but no confirmation. Replace its intent before any fresh staged effect.
    cf_clock || return 1
    CF_REBASE_READY=1
    cf_transition_prepare
    cf_rb_result=$?
    unset CF_REBASE_READY
    [ "$cf_rb_result" = 0 ] || return "$cf_rb_result"
    cf_apply
}
cf_apply() {
    cf_address_refresh || return 1
    cf_durable_record expiry "$CF_EXPIRY_NOW" || return 1
    if [ "${CF_PREPARED_NOOP:-0}" = 1 ];then cf_flush_connections && cf_verify && cf_confirm_apply;return $?;fi
    if [ -z "${CF_TRANSITION-}" ];then
        cf_slot_load;CF_EXPECTED=$(cf_plan) || return 1
        if cf_unchanged_verified;then cf_flush_connections && cf_verify && cf_confirm_apply;return $?;fi
        cf_transition_prepare || return 1
    fi
    cf_transition_read && cf_transition_inventory_check || return 1
    cf_a_phase=$(printf '%s\n' "$CF_TRANSITION" | awk '$1=="PHASE"{print $2}')
    cf_a_digest=$(printf '%s\n' "$CF_TRANSITION" | awk '$1=="NEW"{print $2}')
    [ "$cf_a_digest" = "$CF_DIGEST" ] || { cf_fail transition_not_accepted;return 1; }
    if [ "$cf_a_phase" = rebase_ready ];then cf_transition_rebase;return $?;fi
    cf_transition_fresh || return 1
    cf_a_fresh=$(cf_plan) || return 1
    if [ "$cf_a_fresh" != "$CF_EXPECTED" ] && [ "${CF_CONSERVATIVE_RECOVERY:-0}" != 1 ];then cf_transition_rebase;return $?;fi
    CF_UNION_ADDRESSES=$(printf '%s\n' "$CF_TRANSITION" | awk '/^ADDRESS /{sub(/^ADDRESS /,"");print}')
    cf_a_protection=$(printf '%s\n' "$CF_TRANSITION" | awk '$1=="PROTECTION"{print $2}')
    [ "$cf_a_protection" = "$(sha256sum "$CF_PROTECTED" | awk '{print $1}')" ] || { cf_fail transition_protection_changed;return 1; }
    if [ "$cf_a_phase" = cleanup ] && [ -n "$(cf_rules_snapshot)" ];then
        CF_GUARDED=0;cf_verify || return 1
        if [ "$CF_SLOT" = a ];then cf_a_old=b;else cf_a_old=a;fi
        cf_slot_delete "$cf_a_old" && cf_guard_delete || return 1
        cf_durable_record firewall.owned "couvrefeu-owned-v2
$CF_SLOT" || return 1
        CF_ERROR=;cf_confirm_apply;return $?
    fi
    cf_build_sets && cf_build_plan "$CF_EXPECTED
$CF_GUARD_PLAN" || return 1
    cf_dispatch_initial || return 1
    cf_guard_attach && cf_guard_verify || return 1
    CF_DRAIN_MACS=$CF_UNION;CF_ADDRESS_DATA=$CF_UNION_ADDRESSES
    cf_transition_phase drain_before && cf_flush_connections || return 1
    unset CF_DRAIN_MACS
    cf_transition_phase native && cf_native_apply && cf_guard_verify || return 1
    for cf_a_f in 4 6;do
        cf_dispatch_replace "$cf_a_f" filter cf_fwd "cf2_${CF_SLOT}_f" 2 && cf_dispatch_replace "$cf_a_f" filter cf_input "cf2_${CF_SLOT}_i" 1 || return 1
    done
    cf_dispatch_replace 4 nat cf_dns "cf2_${CF_SLOT}_d" 1 || return 1
    CF_GUARDED=1
    cf_verify || return 1
    CF_DRAIN_MACS=$CF_UNION;CF_ADDRESS_DATA=$CF_UNION_ADDRESSES
    cf_transition_phase drain_after && cf_flush_connections || return 1
    unset CF_DRAIN_MACS
    if [ "${CF_CONSERVATIVE_RECOVERY:-0}" != 1 ];then cf_clock || return 1;fi
    cf_transition_fresh && cf_guard_verify && cf_verify || return 1
    for cf_a_f in 4 6;do
        cf_transition_phase "unguard_$cf_a_f" || return 1
        cf_table "$cf_a_f" -t filter -D cf_fwd -m comment --comment cf:v2 -j "cf2_${CF_SLOT}_g" || { cf_fail guard_remove_failed;return 1; }
    done
    CF_GUARDED=0
    cf_verify || return 1
    cf_transition_phase cleanup || return 1
    if [ "$CF_SLOT" = a ];then cf_a_old=b;else cf_a_old=a;fi
    cf_slot_delete "$cf_a_old" && cf_guard_delete || return 1
    cf_durable_record firewall.owned "couvrefeu-owned-v2
$CF_SLOT" || return 1
    CF_ERROR=
    cf_confirm_apply
}
cf_verify() {
    cf_address_refresh || return 1
    cf_v_fresh=$(cf_plan) || return 1
    if [ -n "${CF_TRANSITION-}" ];then cf_transition_fresh && cf_transition_inventory_check || return 1;fi
    [ "${CF_CONSERVATIVE_RECOVERY:-0}" = 1 ] || [ "$cf_v_fresh" = "$CF_EXPECTED" ] || { cf_fail address_observation_changed;return 1; }
    for cf_v_suffix in k p d4 d6;do
        cf_v_set=cf2_${CF_SLOT}_$cf_v_suffix
        case $cf_v_suffix in k)cf_v_desired=$(cf_kids);cf_v_type=hash:mac;cf_v_family=inet;;p)cf_v_desired=$(cf_effective_macs);cf_v_type=hash:mac;cf_v_family=inet;;d4)cf_v_desired=$(cf_desired_set cf_doh);cf_v_type=hash:ip;cf_v_family=inet;;d6)cf_v_desired=$(cf_desired_set cf_doh6);cf_v_type=hash:ip;cf_v_family=inet6;;esac
        cf_v_actual=$(cf_set_members "$cf_v_set") || return 1
        [ "$cf_v_actual" = "$cf_v_desired" ] || { cf_fail set_drift;return 1; }
        cf_v_header=$(cf_backend ipset save "$cf_v_set") || return 1
        printf '%s\n' "$cf_v_header" | awk -v s="$cf_v_set" -v type="$cf_v_type" -v family="$cf_v_family" '$1=="create"&&$2==s&&$3==type{f="inet";for(i=4;i<NF;i++)if($i=="family")f=$(i+1);if(f==family)yes=1}END{exit !yes}' || { cf_fail set_type_drift;return 1; }
    done
    for cf_v_pair in '4 filter f cf_fwd forwarding_rule' '6 filter f cf_fwd forwarding_rule' '4 filter i cf_input input_rule' '6 filter i cf_input input_rule' '4 nat d cf_dns prerouting_rule';do
        set -- $cf_v_pair
        cf_v_f=$1;cf_v_t=$2;cf_v_gen=cf2_${CF_SLOT}_$3;cf_v_dispatch=$4;cf_v_parent=$5
        cf_v_actual=$(cf_dispatch_rules "$cf_v_f" "$cf_v_t" "$cf_v_gen") || { cf_fail rule_inspection_failed;return 1; }
        cf_v_desired=$(printf '%s\n' "$CF_EXPECTED" | awk -F '\t' -v f="$cf_v_f" -v t="$cf_v_t" -v c="$cf_v_gen" '$1==f&&$2==t&&$3==c{print "-A " c " " $4}' | cf_normal_rules)
        [ "$cf_v_actual" = "$cf_v_desired" ] || { cf_fail rule_drift;return 1; }
        cf_v_actual=$(cf_dispatch_rules "$cf_v_f" "$cf_v_t" "$cf_v_dispatch") || return 1
        cf_v_desired="-A $cf_v_dispatch -m comment --comment cf:v2 -j $cf_v_gen"
        if [ "$CF_GUARDED" = 1 ] && [ "$cf_v_dispatch" = cf_fwd ];then cf_v_desired="-A cf_fwd -m comment --comment cf:v2 -j cf2_${CF_SLOT}_g
$cf_v_desired";fi
        [ "$cf_v_actual" = "$(printf '%s\n' "$cf_v_desired" | cf_normal_rules)" ] || { cf_fail dispatcher_drift;return 1; }
        cf_v_lines=$(cf_dispatch_rules "$cf_v_f" "$cf_v_t" "$cf_v_parent") || return 1
        [ "$(printf '%s\n' "$cf_v_lines" | awk 'NR==1{print}')" = "$(printf '%s\n' "-A $cf_v_parent $(cf_hook_args "$cf_v_dispatch") -j $cf_v_dispatch" | cf_normal_rules)" ] || { cf_fail hook_drift;return 1; }
    done
    for cf_v_f in 4 6;do cf_parent_order "$cf_v_f" filter FORWARD forwarding_rule && cf_parent_order "$cf_v_f" filter INPUT input_rule || return 1;done
    cf_parent_order 4 nat PREROUTING prerouting_rule && cf_native_verify && cf_reference_guard && cf_reference_guard_v2 || return 1
    CF_IPV6_OK=true;CF_CONNTRACK_OK=true
    [ "$CF_ADDRESS_OK" = true ] || { cf_fail incomplete_address_coverage;return 1; }
}
cf_recovery_rules() { cf_transition_read && cf_transition_inventory_check; }
cf_cleanup_sets_guard() { cf_transition_inventory_check; }
cf_cleanup_inventory() {
    printf '%s\n' 'CLEANUP 1'
    cf_ci_rules=$(cf_rules_snapshot) || return 1
    printf '%s\n' "$cf_ci_rules" | awk '$4=="-N"{print "CHAIN " $1 " " $2 " " $3}$4=="-A"{print "RULE " $0}'
    cf_ci_sets=$(cf_backend ipset save) || return 1
    printf '%s\n' "$cf_ci_sets" | awk '($1=="create"||$1=="add")&&$2~/^cf2_[ab]_(k|p|d4|d6|u)$/{print "IPSET " $2 " " $0}' | sort
}
cf_kernel_baseline_digest() {
    # Capture raw complete inventories; counters do not occur in -S output.
    cf_kb_inventory=$(
        for cf_kb_f in 4 6;do
            for cf_kb_t in filter nat mangle raw;do
                printf 'TABLE %s %s\n' "$cf_kb_f" "$cf_kb_t"
                cf_table "$cf_kb_f" -t "$cf_kb_t" -S || exit 1
            done
        done
        printf '%s\n' IPSET
        cf_backend ipset save || exit 1
        printf '%s\n' UCI
        cf_backend uci -q show firewall || exit 1
        printf '%s\n' PENDING
        cf_backend uci -q changes firewall || exit 1
    ) || { cf_fail preflight_baseline_inspection_failed;return 1; }
    printf '%s\n' "$cf_kb_inventory" | sha256sum | awk '{print $1}'
}
cf_preflight_baseline_verify() {
    [ "${CF_INSTALL_AUTH:-0}" = 1 ] || { cf_fail preflight_baseline_requires_installer;return 1; }
    for cf_pb_name in firewall.owned firewall.intent firewall.snapshot firewall.cleanup confirmed;do
        [ ! -e "$CF_RUNTIME/$cf_pb_name" ] && [ ! -L "$CF_RUNTIME/$cf_pb_name" ] || { cf_fail unsafe_preflight_baseline;return 1; }
    done
    cf_safe_file "$CF_RUNTIME/firewall.preflight" && [ "$(wc -c < "$CF_RUNTIME/firewall.preflight")" -le 512 ] || { cf_fail unsafe_preflight_baseline;return 1; }
    CF_PREFLIGHT_RECORD=$(awk -v generation="${CF_GENERATION:--}" -v state="$CF_DIGEST" '
        NR==1&&$0!="PREFLIGHT 1"{exit 2}
        NR==2&&$0!="GENERATION " generation{exit 2}
        NR==3&&$0!="STATE " state{exit 2}
        NR==4&&($1!="KERNEL"||NF!=2||length($2)!=64||$2~/[^0-9a-f]/){exit 2}
        {print}END{if(NR!=4)exit 2}' "$CF_RUNTIME/firewall.preflight") || { cf_fail unsafe_preflight_baseline;return 1; }
    cf_pb_kernel=$(cf_kernel_baseline_digest) || return 1
    [ "$cf_pb_kernel" = "$(printf '%s\n' "$CF_PREFLIGHT_RECORD" | awk 'NR==4{print $2}')" ] || { cf_fail preflight_baseline_drift;return 1; }
}
cf_preflight_baseline_prepare() {
    if [ -e "$CF_RUNTIME/firewall.preflight" ] || [ -L "$CF_RUNTIME/firewall.preflight" ];then cf_preflight_baseline_verify;return $?;fi
    [ "${CF_INSTALL_AUTH:-0}" = 1 ] && [ "${cf_action-}" = apply-fw ] || return 0
    # Durable ownership/transition records already fence any previous effects.
    for cf_pb_name in firewall.owned firewall.intent firewall.snapshot firewall.cleanup confirmed;do
        [ ! -e "$CF_RUNTIME/$cf_pb_name" ] && [ ! -L "$CF_RUNTIME/$cf_pb_name" ] || return 0
    done
    cf_pb_kernel=$(cf_kernel_baseline_digest) || return 1
    CF_PREFLIGHT_RECORD="PREFLIGHT 1
GENERATION ${CF_GENERATION:--}
STATE $CF_DIGEST
KERNEL $cf_pb_kernel"
    cf_durable_record firewall.preflight "$CF_PREFLIGHT_RECORD"
}
cf_preflight_baseline_clear() {
    [ ! -e "$CF_RUNTIME/firewall.preflight" ] && [ ! -L "$CF_RUNTIME/firewall.preflight" ] && return 0
    cf_preflight_baseline_verify && platform_initial_write && rm -f "$CF_RUNTIME/firewall.preflight" && cf_backend sync || { cf_fail preflight_baseline_invalidation_failed;return 1; }
}
cf_zero_owned_kernel() {
    # Absence of a marker is never evidence of absence of kernel effects.
    for cf_zk_f in 4 6;do
        for cf_zk_t in filter nat mangle raw;do
            cf_zk_rules=$(cf_table "$cf_zk_f" -t "$cf_zk_t" -S) || return 1
            printf '%s\n' "$cf_zk_rules" | awk 'function owned(s){return s~/^(cf_fwd|cf_input|cf_dns|cf2_[ab]_[figd])$/}$1=="-N"&&owned($2){exit 1}$1=="-A"{if(owned($2))exit 1;for(i=3;i<NF;i++)if(($i=="-j"||$i=="-g")&&owned($(i+1))||$i=="--match-set"&&$(i+1)~/^(cf_kids|cf_paused|cf_doh|cf_doh6|cf2_[ab]_(k|p|d4|d6|u))$/)exit 1}' || return 1
        done
    done
    cf_zk_sets=$(cf_backend ipset save) || return 1
    printf '%s\n' "$cf_zk_sets" | awk '$2~/^(cf_kids|cf_paused|cf_doh|cf_doh6|cf2_[ab]_(k|p|d4|d6|u))$/{exit 1}$1=="add"&&$3~/^cf2_[ab]_(k|p|d4|d6|u)$/{exit 1}' || return 1
    cf_zk_uci=$(cf_backend uci -q show firewall) || return 1
    printf '%s\n' "$cf_zk_uci" | awk -F '[.=]' '$1=="firewall"&&$2~/^cf_sched_/{exit 1}' || return 1
    cf_zk_pending=$(cf_backend uci -q changes firewall) || return 1
    [ -z "$cf_zk_pending" ]
}
cf_zero_owned_runtime() (
    # Globbing is scoped to enumeration; rule argument splitting stays noglob.
    set +f
    for cf_zr_file in "$CF_RUNTIME"/* "$CF_RUNTIME"/.[!.]* "$CF_RUNTIME"/..?*;do
        [ -e "$cf_zr_file" ] || [ -L "$cf_zr_file" ] || continue
        case ${cf_zr_file##*/} in
            error|expiry|schedule.clock)cf_safe_file "$cf_zr_file" || return 1;;
            firewall.intent)[ "${CF_ZERO_DESCRIPTOR:-0}" = 1 ] && cf_safe_file "$cf_zr_file" || return 1;printf '%s\n' "$cf_zr_file";;
            firewall.preflight)[ "${CF_ZERO_BASELINE:-0}" = 1 ] && cf_safe_file "$cf_zr_file" || return 1;;
            .intent.*)
                cf_zr_pid=${cf_zr_file##*/};cf_zr_pid=${cf_zr_pid#.intent.}
                case $cf_zr_pid in ''|*[!0-9]*)return 1;;esac
                cf_safe_file "$cf_zr_file" || return 1
                cf_zr_content=$(awk '{print}' "$cf_zr_file")
                if [ "${CF_ZERO_DESCRIPTOR:-0}" = 1 ];then
                    [ "$cf_zr_content" = "$CF_TRANSITION" ] || [ "$cf_zr_content" = "couvrefeu-owned-v2
$CF_SLOT" ] || return 1
                elif [ "${CF_ZERO_BASELINE:-0}" = 1 ];then [ "$cf_zr_content" = "$CF_PREFLIGHT_RECORD" ] || return 1
                else return 1;fi
                printf '%s\n' "$cf_zr_file";;
            lock)
                cf_private_dir "$cf_zr_file" && cf_safe_file "$cf_zr_file/pid" && [ "$(awk 'NR==1{print}' "$cf_zr_file/pid")" = "$$" ] || return 1
                for cf_zr_child in "$cf_zr_file"/* "$cf_zr_file"/.[!.]* "$cf_zr_file"/..?*;do
                    [ -e "$cf_zr_child" ] || [ -L "$cf_zr_child" ] || continue
                    [ "${cf_zr_child##*/}" = pid ] || return 1
                done;;
            *)return 1;;
        esac
    done
)
cf_remove_fw() {
    CF_ZERO_OWNED=false
    if ! cf_ownership_valid;then
        [ ! -e "$CF_RUNTIME/firewall.owned" ] && [ ! -L "$CF_RUNTIME/firewall.owned" ] || { cf_fail unsafe_ownership_record;return 1; }
        CF_ZERO_DESCRIPTOR=0
        CF_ZERO_BASELINE=0
        if [ -e "$CF_RUNTIME/firewall.preflight" ] || [ -L "$CF_RUNTIME/firewall.preflight" ];then
            cf_preflight_baseline_verify || return 1
            CF_ZERO_BASELINE=1
        fi
        if [ -e "$CF_RUNTIME/firewall.intent" ] || [ -L "$CF_RUNTIME/firewall.intent" ];then
            cf_transition_read || return 1
            printf '%s\n' "$CF_TRANSITION" | awk '$1=="PHASE"&&$2=="staging"{stage=1}$1=="BEFORE"&&$2!="SCHEDULE"{bad=1}END{exit !stage||bad}' || { cf_fail unsafe_zero_owned_transition;return 1; }
            CF_ZERO_DESCRIPTOR=1
        fi
        cf_rf_zero_files=$(cf_zero_owned_runtime) || { cf_fail unsafe_zero_owned_runtime;return 1; }
        if [ "$CF_ZERO_BASELINE" != 1 ];then cf_zero_owned_kernel || { cf_fail zero_owned_kernel_unproven;return 1; };fi
        while IFS= read -r cf_rf_file;do
            [ -z "$cf_rf_file" ] && continue
            platform_initial_write
            rm -f "$cf_rf_file" || return 1
        done <<EOZ
$cf_rf_zero_files
EOZ
        cf_backend sync || return 1
        cf_rpc_checkpoint after_zero_owned_proof
        CF_ZERO_OWNED=true;return 0
    fi
    if [ -e "$CF_RUNTIME/firewall.intent" ];then cf_transition_read && cf_transition_inventory_check || return 1;fi
    cf_reference_guard_v2 || return 1
    if [ -e "$CF_RUNTIME/firewall.cleanup" ];then cf_cleanup_verify || return 1;else
        if [ ! -e "$CF_RUNTIME/firewall.intent" ];then
            cf_rf_now=$(cf_snapshot) || return 1
            cf_safe_file "$CF_RUNTIME/firewall.snapshot" && [ "$cf_rf_now" = "$(awk '{print}' "$CF_RUNTIME/firewall.snapshot")" ] || { cf_fail cleanup_drift;return 1; }
        fi
        cf_cleanup_begin || return 1
    fi
    for cf_rf_f in 4 6;do cf_remove_one "$cf_rf_f" filter forwarding_rule cf_fwd && cf_remove_one "$cf_rf_f" filter input_rule cf_input || return 1;done
    cf_remove_one 4 nat prerouting_rule cf_dns || return 1
    cf_slot_delete a && cf_slot_delete b || return 1
    cf_rf_remaining=$(cf_cleanup_inventory) || return 1
    [ "$cf_rf_remaining" = 'CLEANUP 1' ] || { cf_fail cleanup_incomplete;return 1; }
    rm -f "$CF_RUNTIME/firewall.owned" "$CF_RUNTIME/firewall.snapshot" "$CF_RUNTIME/confirmed" "$CF_RUNTIME/error" "$CF_RUNTIME/expiry" "$CF_RUNTIME/firewall.intent" "$CF_RUNTIME/firewall.cleanup" "$CF_RUNTIME/schedule.clock" && cf_backend sync
}

# Journal helper inherits shell-local admission in an isolated subshell. An
# independently executed helper has no admission and cannot borrow these facts.
cf_install_journal() (
    [ "${CF_PLATFORM_ADMITTED:-0}" = 1 ] || exit 2
    platform_verify_modules "$CF_LIB"
    CF_PLATFORM_CALLER_PID=$$
    CF_PLATFORM_NESTED=1
    CF_PLATFORM_LOCKED=0
    # shellcheck disable=SC1091
    . "$CF_LIB/install-common.sh"
)
