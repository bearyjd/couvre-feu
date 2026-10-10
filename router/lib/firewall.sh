# shellcheck disable=SC2034,SC2015
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
    function rotate(days,a,n,i,j,d,out,mark){n=split(days,a,",");split("Mon Tue Wed Thu Fri Sat Sun",d," ");for(i=1;i<=n;i++)for(j=1;j<=7;j++)if(a[i]==d[j])mark[j%7+1]=1;for(j=1;j<=7;j++)if(mark[j])out=out (out==""?"":",") d[j];return out}
    function emit(p,m,d,s,e,n){n=++number[p];printf "cf_sched_%s_%d\t%s\t%s\t%s\t%s\t%s\n",p,n,p,m,d,clock(s),clock(e)}
    $1=="P"&&$3!="-"{mac[$2]=mac[$2] " " $3}
    $1=="S"{s=secs($5);e=secs($6);n=split(mac[$2],a," ");for(i=1;i<=n;i++)if(a[i]!=""){if(s<e)emit($2,a[i],$4,s,e-1);else{emit($2,a[i],$4,s,86399);if(e>0)emit($2,a[i],rotate($4),0,e-1)}}}'
}
cf_plan() {
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
    printf '%s\n' "$CF_POLICY" | awk -F '\t' -v now="$CF_EXPIRY_NOW" '$1=="P"&&$3!="-"{mac[$2]=mac[$2] " " $3}$1=="A"&&($3==0||$3>now){paused[$2]=1}END{for(p in paused){n=split(mac[p],a," ");for(i=1;i<=n;i++)if(a[i]!="")print a[i]}}' | sort -u
}
cf_kids() { printf '%s\n' "$CF_POLICY" | awk -F '\t' '$1=="P"&&$3!="-"{print $3}' | sort -u; }
cf_desired_set() {
    case $1 in cf_kids)cf_kids;;cf_paused)cf_effective_macs;;cf_doh)printf '%s\n' "$CF_POLICY" | awk -F '\t' '$1=="D4"{print $2}' | sort -u;;cf_doh6)printf '%s\n' "$CF_POLICY" | awk -F '\t' '$1=="D6"{print $2}' | sort -u;;*)return 1;;esac
}
cf_effective_digest() { { printf '%s\n' "$CF_DIGEST";cf_effective_macs;printf '%s\n' "$CF_EXPECTED"; } | sha256sum | awk '{print $1}'; }
cf_table() { cf_t_family=$1;shift;if [ "$cf_t_family" = 4 ];then cf_backend iptables "$@";else cf_backend ip6tables "$@";fi; }
cf_normal_rules() {
    # iptables serializes built-in selectors before modules, uppercases MACs,
    # inserts protocol modules and prints default REJECT options. Canonicalize
    # complete option fragments; retain all unrecognized fragments as drift.
    awk '
    function days(s,a,d,n,i,j,out,mark){n=split(s,a,",");split("Mon Tue Wed Thu Fri Sat Sun",d," ");for(i=1;i<=n;i++)for(j=1;j<=7;j++)if(a[i]==d[j])mark[j]=1;for(j=1;j<=7;j++)if(mark[j])out=out (out==""?"":",") d[j];return out}
    {
        sub(/--comment "cf:v1"/,"--comment cf:v1")
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
cf_ownership_valid() {
    cf_safe_file "$CF_RUNTIME/firewall.owned" || return 1
    [ "$(awk '{print}' "$CF_RUNTIME/firewall.owned")" = 'couvrefeu-owned-v1' ]
}
cf_parent_order() {
    cf_chain_rules=$(cf_table "$1" -t "$2" -S "$3") || { cf_fail required_hook_missing;return 1; }
    printf '%s\n' "$cf_chain_rules" | awk -v mode=parent -v chain="$3" -v hook="$4" -f "$CF_LIB/rules.awk" || { cf_fail unsafe_parent_hook_semantics;return 1; }
}
cf_hook_args() {
    # forwarding must carry both LAN egress and WAN replies; rules guard each direction.
    if [ "$1" = cf_fwd ];then printf '%s\n' '-m comment --comment cf:v1';else printf '%s\n' '-i br-lan -m comment --comment cf:v1';fi
}
cf_preflight() {
    for cf_dep in iptables ip6tables ipset uci conntrack ip fw3;do
        cf_backend_available "$cf_dep" || { cf_fail missing_dependencies;return 1; }
    done
    cf_network || return 1
    for cf_f in 4 6; do
        cf_parent_order "$cf_f" filter FORWARD forwarding_rule || return 1
        cf_parent_order "$cf_f" filter INPUT input_rule || return 1
        cf_table "$cf_f" -t filter -S forwarding_rule >/dev/null || { cf_fail required_hook_missing;return 1; }
        cf_table "$cf_f" -t filter -S input_rule >/dev/null || { cf_fail required_hook_missing;return 1; }
    done
    cf_parent_order 4 nat PREROUTING prerouting_rule || return 1
    cf_table 4 -t nat -S prerouting_rule >/dev/null || { cf_fail required_hook_missing;return 1; }
    CF_IPV6_OK=true
    cf_backend_available conntrack || { cf_fail conntrack_unavailable;return 1; }
    CF_CONNTRACK_OK=true
    if ! cf_ownership_valid; then
        [ ! -e "$CF_RUNTIME/firewall.owned" ] && [ ! -L "$CF_RUNTIME/firewall.owned" ] || { cf_fail unsafe_ownership_record;return 1; }
        for cf_f in 4 6;do
            for cf_chain in cf_fwd cf_input;do
                if cf_table "$cf_f" -t filter -S "$cf_chain" >/dev/null 2>&1;then cf_fail foreign_chain_collision;return 1;fi
            done
        done
        if cf_table 4 -t nat -S cf_dns >/dev/null 2>&1;then cf_fail foreign_chain_collision;return 1;fi
        for cf_set in cf_kids cf_paused cf_doh cf_doh6;do
            if cf_backend ipset save "$cf_set" >/dev/null 2>&1;then cf_fail foreign_set_collision;return 1;fi
        done
    fi
    cf_uci_pending=$(cf_backend uci -q changes firewall) || { cf_fail uci_inspection_failed;return 1; }
    [ -z "$cf_uci_pending" ] || { cf_fail foreign_uci_pending_changes;return 1; }
    cf_uci_existing=$(cf_backend uci -q show firewall) || { cf_fail uci_inspection_failed;return 1; }
    cf_uci_sections=$(printf '%s\n' "$cf_uci_existing" | awk -F '[.=]' '$1=="firewall"&&$2~/^cf_sched_/&&NF==3{print $2}' | sort -u)
    for cf_section in $cf_uci_sections;do
        cf_meta=$(cf_backend uci -q get "firewall.$cf_section.couvrefeu_owner") || { cf_fail foreign_schedule_collision;return 1; }
        [ "$cf_meta" = v1 ] && cf_ownership_valid || { cf_fail foreign_schedule_collision;return 1; }
    done
    cf_reference_guard || return 1
    cf_address_refresh || return 1
    case ${cf_action-} in pause|sync)
        [ "$CF_ADDRESS_OK" = true ] || { cf_fail incomplete_address_coverage;return 1; };;
    esac
    cf_preflight_plan=$(cf_plan) || { cf_fail unsafe_address_attribution;return 1; }
    if [ -e "$CF_RUNTIME/firewall.intent" ] || [ -L "$CF_RUNTIME/firewall.intent" ];then
        cf_recovery_rules || { cf_fail interrupted_rule_drift;return 1; }
    fi
    # No ownership marker may authorize unrelated externally added rules.
    if cf_safe_file "$CF_RUNTIME/firewall.snapshot";then
        cf_previous=$(awk '/^RULE /{sub(/^RULE /,"");print}' "$CF_RUNTIME/firewall.snapshot")
        cf_current=$(cf_rules_snapshot) || return 1
        # Firewall reload removes chains: completely absent objects can be rebuilt.
        if [ -n "$cf_current" ] && [ "$cf_current" != "$cf_previous" ];then
            cf_recovery_rules || { cf_fail owned_rule_drift;return 1; }
        fi
    elif [ -e "$CF_RUNTIME/firewall.snapshot" ];then cf_fail unsafe_snapshot;return 1;fi
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
cf_recovery_rules() {
    cf_safe_file "$CF_RUNTIME/firewall.intent" || return 1
    [ "$(wc -c < "$CF_RUNTIME/firewall.intent")" -le 262144 ] || return 1
    cf_old=
    if cf_safe_file "$CF_RUNTIME/firewall.snapshot";then cf_old=$(awk '/^RULE /{sub(/^RULE /,"");print}' "$CF_RUNTIME/firewall.snapshot");fi
    cf_intent=$(awk -F '\t' '{if(NF!=4||$1!~/^[46]$/||$2!~/^(filter|nat)$/||$3!~/^cf_(fwd|input|dns)$/)exit 2;print}' "$CF_RUNTIME/firewall.intent") || return 1
    for cf_f in 4 6;do
        for cf_chain in cf_fwd cf_input;do
            cf_partial_rule "$cf_f" filter "$cf_chain" || return 1
        done
    done
    cf_partial_rule 4 nat cf_dns
}
cf_partial_rule() {
    cf_recovery_f=$1;cf_recovery_t=$2;cf_recovery_c=$3
    cf_partial_inventory=$(cf_table "$1" -t "$2" -S) || return 1
    cf_partial=$(printf '%s\n' "$cf_partial_inventory" | cf_normal_rules | awk -v c="$3" '$1=="-A"&&$2==c{print}')
    cf_allowed_old=$(printf '%s\n' "$cf_old" | awk -v f="$1" -v t="$2" -v c="$3" '$1==f&&$2==t&&$3==c{sub(/^[^ ]+ [^ ]+ [^ ]+ /,"");print}' | awk '/^-A /{print}')
    [ "$cf_partial" = "$cf_allowed_old" ] && return 0
    cf_allowed_new=$(printf '%s\n' "$cf_intent" | awk -F '\t' -v f="$1" -v t="$2" -v c="$3" '$1==f&&$2==t&&$3==c{print "-A " c " " $4}' | cf_normal_rules)
    [ -z "$cf_partial" ] && return 0
    cf_n=$(printf '%s\n' "$cf_partial" | wc -l)
    cf_prefix=$(printf '%s\n' "$cf_allowed_new" | awk -v n="$cf_n" 'NR<=n{print}')
    [ "$cf_partial" = "$cf_prefix" ]
}
cf_write_intent() {
    cf_temp=$CF_RUNTIME/.intent.$$
    [ ! -e "$cf_temp" ] && [ ! -L "$cf_temp" ] || { cf_fail unsafe_temporary;return 1; }
    printf '%s\n' "$CF_EXPECTED" > "$cf_temp" && chmod 600 "$cf_temp" && mv -f "$cf_temp" "$CF_RUNTIME/firewall.intent" || { cf_fail intent_write_failed;return 1; }
}
cf_rules_snapshot() {
    for cf_snapshot_pair in '4 filter' '6 filter' '4 nat';do
        # shellcheck disable=SC2086
        set -- $cf_snapshot_pair
        cf_lines=$(cf_table "$1" -t "$2" -S) || return 1
        printf '%s\n' "$cf_lines" | cf_normal_rules | awk -v f="$1" -v t="$2" '($1=="-A"||$1=="-N")&&(($2=="cf_fwd"||$2=="cf_input")&&t=="filter"||$2=="cf_dns"&&t=="nat"){print f " " t " " $2 " " $0}'
    done
}
cf_snapshot() {
    cf_snapshot_rules=$(cf_rules_snapshot) || return 1
    printf '%s\n' "$cf_snapshot_rules" | awk 'NF{print "RULE " $0}'
    for cf_set in cf_kids cf_paused cf_doh cf_doh6;do
        cf_members=$(cf_set_members "$cf_set") || return 1
        cf_snapshot_set=$(cf_backend ipset save "$cf_set") || return 1
        printf '%s\n' "$cf_snapshot_set" | awk -v s="$cf_set" '$1=="create"&&$2==s{print "SETDEF " $0}'
        printf '%s\n' "$cf_members" | awk -v s="$cf_set" 'NF{print "SET " s " " $0}'
    done
    cf_schedule_specs | awk -F '\t' 'NF{print "SCHEDULE " $0}'
}
cf_native_apply() {
    cf_specs=$(cf_schedule_specs) || return 1
    cf_new_native=$(printf '%s\n' "$cf_specs" | sha256sum | awk '{print $1}')
    cf_old_native=
    if cf_safe_file "$CF_RUNTIME/firewall.snapshot";then cf_old_native=$(awk '/^SCHEDULE /{sub(/^SCHEDULE /,"");print}' "$CF_RUNTIME/firewall.snapshot" | sha256sum | awk '{print $1}');fi
    # Empty initial policy needs no UCI write or reload.
    if [ "$cf_new_native" = "$cf_old_native" ] || { [ -z "$cf_specs" ] && [ -z "$cf_uci_sections" ]; };then return 0;fi
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
        sh "$cf_install_helper" firewall-prepare "$cf_stage/firewall" || { cf_fail native_journal_failed;return 1; }
    fi
    mv -f "$cf_stage/firewall" "$CF_BASE/etc/config/firewall" || { cf_fail native_commit_failed;return 1; }
    rmdir "$cf_stage/.delta" && rmdir "$cf_stage" || return 1
    if [ -e "$CF_DIR/backup/ready" ];then sh "$cf_install_helper" firewall-commit || { cf_fail native_journal_failed;return 1; };fi
    CF_RELOAD_TOKEN=$(printf '%s\n' "$$:$CF_DIGEST:$CF_NOW_VALUE" | sha256sum | awk '{print $1}')
    printf '%s\n' "$CF_RELOAD_TOKEN" > "$CF_RUNTIME/lock/reload" || return 1
    export CF_RELOAD_TOKEN
    cf_backend fw3 -q reload || { unset CF_RELOAD_TOKEN;cf_fail native_reload_failed;return 1; }
    unset CF_RELOAD_TOKEN
    rm -f "$CF_RUNTIME/lock/reload"
}
cf_chain_prepare() {
    if ! cf_table "$1" -t "$2" -S "$3" >/dev/null 2>&1;then cf_table "$1" -t "$2" -N "$3" || return 1;fi
    cf_table "$1" -t "$2" -F "$3"
}
cf_hook() {
    cf_f=$1;cf_t=$2;cf_parent=$3;cf_chain=$4
    # Fixed helper fragments contain only validated constant tokens; split intentionally.
    # Delete only this exact owned jump, including our immutable comment.
    cf_parent_lines=$(cf_table "$cf_f" -t "$cf_t" -S "$cf_parent") || return 1
    cf_exact_hook=$(printf '%s\n' "-A $cf_parent $(cf_hook_args "$cf_chain") -j $cf_chain" | cf_normal_rules)
    cf_count=$(printf '%s\n' "$cf_parent_lines" | cf_normal_rules | awk -v exact="$cf_exact_hook" '$0==exact{n++}END{print n+0}')
    while [ "$cf_count" -gt 0 ];do
        # shellcheck disable=SC2086,SC2046
        cf_table "$cf_f" -t "$cf_t" -D "$cf_parent" $(cf_hook_args "$cf_chain") -j "$cf_chain" || return 1
        cf_count=$((cf_count-1))
    done
    # Refuse unrelated jumps targeting our chain instead of deleting them.
    printf '%s\n' "$cf_parent_lines" | cf_normal_rules | awk -v exact="$cf_exact_hook" -v c="$cf_chain" 'index($0," -j " c)>0&&$0!=exact{exit 1}' || { cf_fail foreign_hook_collision;return 1; }
    # shellcheck disable=SC2086,SC2046
    cf_table "$cf_f" -t "$cf_t" -I "$cf_parent" 1 $(cf_hook_args "$cf_chain") -j "$cf_chain"
}
cf_sets_apply() {
    for cf_set in cf_kids cf_paused cf_doh cf_doh6;do
        case $cf_set in cf_kids|cf_paused)cf_type=hash:mac;cf_family=;;cf_doh)cf_type=hash:ip;cf_family=inet;;cf_doh6)cf_type=hash:ip;cf_family=inet6;;esac
        if [ -n "$cf_family" ];then cf_backend ipset create "$cf_set" "$cf_type" family "$cf_family" -exist || return 1;else cf_backend ipset create "$cf_set" "$cf_type" -exist || return 1;fi
        cf_backend ipset flush "$cf_set" || return 1
        cf_members=$(cf_desired_set "$cf_set") || return 1
        for cf_member in $cf_members;do cf_backend ipset add "$cf_set" "$cf_member" -exist || return 1;done
    done
}
cf_flush_connections() {
    cf_paused=$(cf_effective_macs)
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
cf_apply() {
    cf_address_refresh || return 1
    cf_temp=$CF_RUNTIME/.expiry.$$
    [ ! -e "$cf_temp" ] && [ ! -L "$cf_temp" ] || return 1
    printf '%s\n' "$CF_EXPIRY_NOW" > "$cf_temp" && chmod 600 "$cf_temp" && mv -f "$cf_temp" "$CF_RUNTIME/expiry" || { cf_fail expiry_record_failed;return 1; }
    CF_EXPECTED=$(cf_plan) || { cf_fail plan_failed;return 1; }
    cf_write_intent || return 1
    if ! cf_ownership_valid;then
        [ ! -e "$CF_RUNTIME/firewall.owned" ] || return 1
        printf '%s\n' 'couvrefeu-owned-v1' > "$CF_RUNTIME/firewall.owned" || return 1
    fi
    cf_native_apply || { [ -n "$CF_ERROR" ] || cf_fail native_apply_failed;return 1; }
    cf_sets_apply || { cf_fail set_apply_failed;return 1; }
    for cf_f in 4 6;do
        for cf_chain in cf_fwd cf_input;do cf_chain_prepare "$cf_f" filter "$cf_chain" || { cf_fail chain_apply_failed;return 1; };done
    done
    cf_chain_prepare 4 nat cf_dns || { cf_fail chain_apply_failed;return 1; }
    cf_tab=$(printf '\t')
    while IFS="$cf_tab" read -r cf_f cf_t cf_chain cf_rule;do
        [ -n "$cf_f" ] || continue
        # Words originate exclusively in a bounded validated plan, never shell evaluation.
        # shellcheck disable=SC2086
        set -- $cf_rule
        cf_table "$cf_f" -t "$cf_t" -A "$cf_chain" "$@" || { cf_fail rule_apply_failed;return 1; }
    done <<EOF
$CF_EXPECTED
EOF
    for cf_f in 4 6;do
        cf_hook "$cf_f" filter forwarding_rule cf_fwd || { cf_fail hook_apply_failed;return 1; }
        cf_hook "$cf_f" filter input_rule cf_input || { cf_fail hook_apply_failed;return 1; }
    done
    cf_hook 4 nat prerouting_rule cf_dns || { cf_fail hook_apply_failed;return 1; }
    cf_flush_connections || return 1
    cf_verify || return 1
    cf_temp=$CF_RUNTIME/.snapshot.$$
    [ ! -e "$cf_temp" ] && [ ! -L "$cf_temp" ] || return 1
    cf_snapshot > "$cf_temp" && chmod 600 "$cf_temp" && mv -f "$cf_temp" "$CF_RUNTIME/firewall.snapshot" || { cf_fail snapshot_failed;return 1; }
    cf_temp=$CF_RUNTIME/.confirmed.$$
    [ ! -e "$cf_temp" ] && [ ! -L "$cf_temp" ] || return 1
    printf '%s %s %s\n' "$CF_REVISION" "$CF_DIGEST" "$(cf_effective_digest)" > "$cf_temp" && chmod 600 "$cf_temp" && mv -f "$cf_temp" "$CF_RUNTIME/confirmed" || { cf_fail confirmation_failed;return 1; }
    [ ! -e "$CF_RUNTIME/error" ] || { cf_safe_file "$CF_RUNTIME/error" && rm -f "$CF_RUNTIME/error"; } || return 1
    cf_safe_file "$CF_RUNTIME/firewall.intent" && rm -f "$CF_RUNTIME/firewall.intent"
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
    [ -n "$cf_specs" ] || return 0
    cf_tab=$(printf '\t')
    while IFS="$cf_tab" read -r cf_name cf_person cf_mac cf_days cf_start cf_stop;do
        [ -n "$cf_name" ] || continue
        for cf_pair in 'couvrefeu_owner=v1' "name=$cf_name" 'src=lan' 'dest=wan' 'target=REJECT' 'proto=all' "src_mac=$cf_mac" "weekdays=$(printf '%s\n' "$cf_days" | tr ',' ' ')" "start_time=$cf_start" "stop_time=$cf_stop" 'utc_time=0' 'enabled=1';do
            cf_key=${cf_pair%%=*};cf_value=${cf_pair#*=}
            cf_actual=$(cf_backend uci -q get "firewall.$cf_name.$cf_key") || { CF_NATIVE_OK=false;cf_fail native_metadata_drift;return 1; }
            [ "$cf_actual" = "$cf_value" ] || { CF_NATIVE_OK=false;cf_fail native_metadata_drift;return 1; }
        done
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
cf_verify() {
    cf_address_refresh || return 1
    cf_fresh_plan=$(cf_plan) || return 1
    [ "$cf_fresh_plan" = "$CF_EXPECTED" ] || { cf_fail address_observation_changed;return 1; }
    [ -n "$CF_EXPECTED" ] || { cf_fail plan_unavailable;return 1; }
    for cf_set in cf_kids cf_paused cf_doh cf_doh6;do
        cf_actual=$(cf_set_members "$cf_set") || return 1
        cf_desired=$(cf_desired_set "$cf_set") || return 1
        [ "$cf_actual" = "$cf_desired" ] || { cf_fail set_drift;return 1; }
        cf_header=$(cf_backend ipset save "$cf_set") || return 1
        case $cf_set in cf_kids|cf_paused)cf_type=hash:mac;;*)cf_type=hash:ip;;esac
        case $cf_set in cf_doh)cf_set_family=inet;;cf_doh6)cf_set_family=inet6;;*)cf_set_family=;;esac
        printf '%s\n' "$cf_header" | awk -v name="$cf_set" -v type="$cf_type" -v family="$cf_set_family" '$1=="create"&&$2==name&&$3==type{f="inet";for(i=4;i<NF;i++)if($i=="family")f=$(i+1);if(family==""||f==family)yes=1}END{exit !yes}' || { cf_fail set_type_drift;return 1; }
    done
    for cf_f in 4 6;do
        for cf_chain in cf_fwd cf_input;do
            cf_actual=$(cf_table "$cf_f" -t filter -S "$cf_chain" | cf_normal_rules | awk '/^-A /{print}')
            cf_desired=$(printf '%s\n' "$CF_EXPECTED" | awk -F '\t' -v f="$cf_f" -v c="$cf_chain" '$1==f&&$2=="filter"&&$3==c{print "-A " c " " $4}' | cf_normal_rules)
            [ "$cf_actual" = "$cf_desired" ] || { cf_fail rule_drift;return 1; }
        done
        for cf_pair in 'forwarding_rule cf_fwd' 'input_rule cf_input';do
            # shellcheck disable=SC2086
            set -- $cf_pair
            cf_lines=$(cf_table "$cf_f" -t filter -S "$1") || return 1
            cf_first=$(printf '%s\n' "$cf_lines" | cf_normal_rules | awk '/^-A /{print;exit}')
            [ "$cf_first" = "$(printf '%s\n' "-A $1 $(cf_hook_args "$2") -j $2" | cf_normal_rules)" ] || { cf_fail hook_drift;return 1; }
            cf_count=$(printf '%s\n' "$cf_lines" | awk -v c="$2" 'index($0," -j " c)>0{n++}END{print n+0}')
            [ "$cf_count" = 1 ] || { cf_fail duplicate_hook;return 1; }
        done
        cf_parent_order "$cf_f" filter FORWARD forwarding_rule || return 1
        cf_parent_order "$cf_f" filter INPUT input_rule || return 1
    done
    cf_actual=$(cf_table 4 -t nat -S cf_dns | cf_normal_rules | awk '/^-A /{print}')
    cf_desired=$(printf '%s\n' "$CF_EXPECTED" | awk -F '\t' '$1==4&&$2=="nat"&&$3=="cf_dns"{print "-A cf_dns " $4}' | cf_normal_rules)
    [ "$cf_actual" = "$cf_desired" ] || { cf_fail dns_rule_drift;return 1; }
    cf_lines=$(cf_table 4 -t nat -S prerouting_rule) || return 1
    cf_first=$(printf '%s\n' "$cf_lines" | cf_normal_rules | awk '/^-A /{print;exit}')
    [ "$cf_first" = "$(printf '%s\n' '-A prerouting_rule -i br-lan -m comment --comment cf:v1 -j cf_dns' | cf_normal_rules)" ] || { cf_fail dns_hook_drift;return 1; }
    cf_parent_order 4 nat PREROUTING prerouting_rule || return 1
    cf_native_verify || return 1
    CF_IPV6_OK=true
    cf_backend_available conntrack || { cf_fail conntrack_unavailable;return 1; }
    CF_CONNTRACK_OK=true
    [ "$CF_ADDRESS_OK" = true ] || { cf_fail incomplete_address_coverage;return 1; }
}
cf_cleanup_sets_guard() {
    cf_cleanup_all_sets=$(cf_backend ipset save) || { cf_fail cleanup_inspection_failed;return 1; }
    for cf_set in cf_kids cf_paused cf_doh cf_doh6;do
        cf_set_data=$(printf '%s\n' "$cf_cleanup_all_sets" | awk -v s="$cf_set" '$2==s{print}')
        [ -n "$cf_set_data" ] || continue
        case $cf_set in cf_kids|cf_paused)cf_cleanup_type=hash:mac;cf_cleanup_family=;;cf_doh)cf_cleanup_type=hash:ip;cf_cleanup_family=inet;;cf_doh6)cf_cleanup_type=hash:ip;cf_cleanup_family=inet6;;esac
        printf '%s\n' "$cf_set_data" | awk -v name="$cf_set" -v type="$cf_cleanup_type" -v family="$cf_cleanup_family" '$1=="create"&&$2==name&&$3==type{f="inet";for(i=4;i<NF;i++)if($i=="family")f=$(i+1);if(family==""||f==family)yes=1}END{exit !yes}' || { cf_fail cleanup_set_drift;return 1; }
        cf_members=$(printf '%s\n' "$cf_set_data" | awk '$1=="add"{print tolower($3)}' | sort -u)
        cf_allowed=$(cf_desired_set "$cf_set")
        if cf_safe_file "$CF_RUNTIME/firewall.snapshot";then
            cf_old_members=$(awk -v s="$cf_set" '$1=="SET"&&$2==s{print $3}' "$CF_RUNTIME/firewall.snapshot")
            cf_allowed=$(printf '%s\n%s\n' "$cf_allowed" "$cf_old_members" | sort -u)
        fi
        printf '%s\n' "$cf_members" | awk -v allowed="$cf_allowed" 'BEGIN{n=split(allowed,a,"\n");for(i=1;i<=n;i++)yes[a[i]]=1}NF&&!yes[$0]{exit 1}' || { cf_fail cleanup_set_drift;return 1; }
    done
}
cf_cleanup_inventory() {
    # Full successful inventories distinguish absent objects from inspection failures.
    printf '%s\n' 'CLEANUP 1'
    for cf_inventory_pair in '4 filter' '6 filter' '4 nat';do
        # shellcheck disable=SC2086
        set -- $cf_inventory_pair
        cf_inventory_f=$1;cf_inventory_t=$2
        cf_inventory_lines=$(cf_table "$1" -t "$2" -S) || return 1
        printf '%s\n' "$cf_inventory_lines" | awk -v f="$1" -v t="$2" '$1=="-N"&&(($2=="cf_fwd"||$2=="cf_input")&&t=="filter"||$2=="cf_dns"&&t=="nat"){print "CHAIN " f " " t " " $2}'
        printf '%s\n' "$cf_inventory_lines" | cf_normal_rules | awk -v f="$cf_inventory_f" -v t="$cf_inventory_t" '$1=="-A"&&(($2=="cf_fwd"||$2=="cf_input")&&t=="filter"||$2=="cf_dns"&&t=="nat"){print "RULE " f " " t " " $2 " " $0}'
    done
    cf_inventory_sets=$(cf_backend ipset save) || return 1
    printf '%s\n' "$cf_inventory_sets" | awk '($1=="create"||$1=="add")&&$2~/^cf_(kids|paused|doh|doh6)$/{print "IPSET " $2 " " $0}' | sort
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
    cf_cleanup_temp=$CF_RUNTIME/.cleanup.$$
    [ ! -e "$cf_cleanup_temp" ] && [ ! -L "$cf_cleanup_temp" ] || { cf_fail unsafe_temporary;return 1; }
    printf '%s\n' "$cf_cleanup_data" > "$cf_cleanup_temp" && chmod 600 "$cf_cleanup_temp" && mv -f "$cf_cleanup_temp" "$CF_RUNTIME/firewall.cleanup" || { cf_fail cleanup_intent_write_failed;return 1; }
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
cf_remove_fw() {
    CF_ZERO_OWNED=false
    if ! cf_ownership_valid;then
        # No mutation records means we never acquired any kernel objects.
        # A foreign collision is preserved and cannot prevent file-only rollback.
        for cf_zero_record in "$CF_RUNTIME"/* "$CF_RUNTIME"/.[!.]* "$CF_RUNTIME"/..?*;do
            [ -e "$cf_zero_record" ] || [ -L "$cf_zero_record" ] || continue
            case ${cf_zero_record##*/} in
                error|expiry)cf_safe_file "$cf_zero_record" || { cf_fail unsafe_zero_owned_runtime;return 1; };;
                lock)
                    cf_private_dir "$cf_zero_record" && cf_safe_file "$cf_zero_record/pid" && [ "$(awk 'NR==1{print}' "$cf_zero_record/pid")" = "$$" ] || { cf_fail unsafe_zero_owned_runtime;return 1; }
                    for cf_zero_lock_record in "$cf_zero_record"/* "$cf_zero_record"/.[!.]* "$cf_zero_record"/..?*;do
                        [ -e "$cf_zero_lock_record" ] || [ -L "$cf_zero_lock_record" ] || continue
                        [ "${cf_zero_lock_record##*/}" = pid ] || { cf_fail unsafe_zero_owned_runtime;return 1; }
                    done;;
                *)cf_fail unsafe_zero_owned_runtime;return 1;;
            esac
        done
        CF_ZERO_OWNED=true
        return 0
    fi
    cf_reference_guard || return 1
    if [ -e "$CF_RUNTIME/firewall.cleanup" ] || [ -L "$CF_RUNTIME/firewall.cleanup" ];then
        cf_cleanup_verify || return 1
    else
        if [ -e "$CF_RUNTIME/firewall.intent" ] || [ -L "$CF_RUNTIME/firewall.intent" ];then
            cf_recovery_rules && cf_cleanup_sets_guard || { cf_fail cleanup_drift;return 1; }
        else
            cf_safe_file "$CF_RUNTIME/firewall.snapshot" || { cf_fail cleanup_unconfirmed;return 1; }
            cf_previous=$(awk '{print}' "$CF_RUNTIME/firewall.snapshot")
            cf_current=$(cf_snapshot) || { cf_fail cleanup_inspection_failed;return 1; }
            [ "$cf_previous" = "$cf_current" ] || { cf_fail cleanup_drift;return 1; }
        fi
        cf_cleanup_begin || return 1
    fi
    for cf_f in 4 6;do
        cf_remove_one "$cf_f" filter forwarding_rule cf_fwd || return 1
        cf_remove_one "$cf_f" filter input_rule cf_input || return 1
    done
    cf_remove_one 4 nat prerouting_rule cf_dns || return 1
    cf_cleanup_sets=$(cf_backend ipset save) || return 1
    for cf_set in cf_kids cf_paused cf_doh cf_doh6;do
        if printf '%s\n' "$cf_cleanup_sets" | awk -v s="$cf_set" '$1=="create"&&$2==s{yes=1}END{exit !yes}';then cf_backend ipset destroy "$cf_set" || return 1;fi
    done
    cf_cleanup_remaining=$(cf_cleanup_inventory) || return 1
    [ "$cf_cleanup_remaining" = 'CLEANUP 1' ] || { cf_fail cleanup_incomplete;return 1; }
    # Uninstaller restores exact native config from its journal; no UCI writes here.
    rm -f "$CF_RUNTIME/firewall.owned" "$CF_RUNTIME/firewall.snapshot" "$CF_RUNTIME/confirmed" "$CF_RUNTIME/error" "$CF_RUNTIME/expiry" "$CF_RUNTIME/firewall.intent" "$CF_RUNTIME/firewall.cleanup"
}
