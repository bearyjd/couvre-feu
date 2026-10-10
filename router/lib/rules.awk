# Strict token-level verifier for supported iptables -S parent/native paths.
# Quoted comments are data. Unknown selectors are rejected, never discarded.
function bad(){failed=1;exit 2}
function tokens(line,    i,c,word,q,started){
    n=0;word="";q=0;started=0
    for(i=1;i<=length(line);i++){
        c=substr(line,i,1)
        if(c=="\\" || c !~ /^[ -~]$/)bad()
        if(c=="\""){q=!q;started=1;continue}
        if(c==" "&&!q){if(started){a[++n]=word;word="";started=0}continue}
        word=word c;started=1
    }
    if(q)bad()
    if(started)a[++n]=word
}
function comment(i){return a[i]=="-m"&&a[i+1]=="comment"&&a[i+2]=="--comment"&&i+3<=n}
function jump_only(target,    i,got){
    got=0
    for(i=3;i<=n;i++){
        if(comment(i)){i+=3;continue}
        if(a[i]=="-j"&&a[i+1]==target&&!got++){i++;continue}
        return 0
    }
    return got==1
}
function current_target(    i,t){
    t=""
    for(i=3;i<=n;i++){
        if(comment(i)){i+=3;continue}
        if(a[i]=="-g"||a[i]=="--goto"||a[i]=="--jump")return "unsupported"
        if(a[i]=="-j"){if(t!=""||i==n)return "unsupported";t=a[++i]}
    }
    return t
}
function input_exception(    i,iface,proto,ni,np){
    if(chain!="INPUT"||current_target()!="ACCEPT")return 0
    # The owned INPUT exception handles only LAN UDP DNS. Positive loopback
    # and ICMP accepts are disjoint; FORWARD has no such protocol exception.
    for(i=3;i<=n;i++){
        if(comment(i)){i+=3;continue}
        if(a[i]=="!")return 0
        if(a[i]=="-i"){if(++ni>1)return 0;iface=a[++i]}
        else if(a[i]=="-p"){if(++np>1)return 0;proto=a[++i]}
    }
    return iface=="lo"||proto=="icmp"||proto=="ipv6-icmp"||proto=="icmpv6"||proto=="58"||proto=="1"
}
function native_rule(    i,k,v,c,macm,timem,commentm,macv,startv,stopv,dayv,tz,proto,jump,rej){
    startv="00:00:00";stopv="23:59:59";dayv="Mon,Tue,Wed,Thu,Fri,Sat,Sun"
    for(i=3;i<=n;i++){
        k=a[i]
        if(k=="-m"){
            v=a[++i]
            if(v=="mac"&&!macm++){continue}
            if(v=="time"&&!timem++){continue}
            if(v=="comment"&&!commentm++){continue}
            return ""
        }
        if(k=="--mac-source"&&macv==""){macv=tolower(a[++i]);continue}
        if(k=="--timestart"&&!seenstart++){startv=a[++i];continue}
        if(k=="--timestop"&&!seenstop++){stopv=a[++i];continue}
        if(k=="--weekdays"&&!seendays++){dayv=a[++i];continue}
        if(k=="--kerneltz"&&!tz++){continue}
        if(k=="--comment"&&c==""){c=a[++i];continue}
        if(k=="-p"&&!proto++&&a[i+1]=="all"){i++;continue}
        if(k=="-j"&&jump==""){jump=a[++i];continue}
        if(k=="--reject-with"&&rej==""){rej=a[++i];continue}
        return ""
    }
    if(macm!=1||timem!=1||commentm!=1||tz!=1||macv!=mac||startv!=start||stopv!=stop||dayv!=days||c!="!fw3: " name)return ""
    if(jump!="REJECT"&&jump!="zone_wan_dest_REJECT")return ""
    if(rej!=""&&(jump!="REJECT"||rej!=(family==4?"icmp-port-unreachable":"icmp6-port-unreachable")))return ""
    return jump
}
function dest_rule(    i,k,out,jump){
    for(i=3;i<=n;i++){
        if(comment(i)){i+=3;continue}
        k=a[i]
        if(k=="-o"&&out==""&&a[i+1]~/^[a-zA-Z0-9_][a-zA-Z0-9_.:-]*$/&&length(a[i+1])<=15){out=a[++i];continue}
        if(k=="-j"&&jump==""){jump=a[++i];continue}
        return 0
    }
    if(jump!="reject")return 0
    if(out==""){allwan=1;return 1}
    if(!wanmember[out]||covered[out]++)return 0
    return 1
}
function reject_rule(    i,k,p,j,rej,pm){
    for(i=3;i<=n;i++){
        if(comment(i)){i+=3;continue}
        k=a[i]
        if(k=="-p"&&p==""){p=a[++i];continue}
        if(k=="-m"&&!pm++&&a[i+1]=="tcp"){i++;continue}
        if(k=="-j"&&j==""){j=a[++i];continue}
        if(k=="--reject-with"&&rej==""){rej=a[++i];continue}
        return 0
    }
    if(j!="REJECT")return 0
    if(p=="tcp"&&rej=="tcp-reset"&&!terminal)return 1
    if(p==""&&pm==0&&(rej==""||rej==(family==4?"icmp-port-unreachable":"icmp6-port-unreachable"))&&!terminal){terminal=1;return 1}
    return 0
}
BEGIN{
    if(mode=="destreject"){
        nw=split(devices,w,"\n")
        for(wi=1;wi<=nw;wi++)if(w[wi]!="")wanmember[w[wi]]=1
    }
}
{
    tokens($0)
    if(n==0)next
    if(a[1]=="-N"&&n==2&&a[2]==chain)next
    if(a[1]=="-P"&&n==3&&a[2]==chain)next
    if(a[1]!="-A"||a[2]!=chain)bad()
    if(mode=="parent"){
        target=current_target()
        if(target==hook){if(++hooks!=1||!jump_only(hook))bad();found=1;next}
        if(!found&&target!="DROP"&&target!="REJECT"&&target!="LOG"&&!input_exception())bad()
    }else if(mode=="native"||mode=="prefix"){
        matchname=0
        for(i=3;i<n;i++)if(a[i]=="--comment"&&a[i+1]=="!fw3: " name)matchname=1
        if(matchname){seenstart=seenstop=seendays=0;jump=native_rule();if(jump==""||++matches>1)bad();result=jump;found=1}
        else if(mode=="prefix"&&!found){
            target=current_target()
            if(target=="ACCEPT"||target=="RETURN"||target=="unsupported"||target=="")bad()
            if(target!="DROP"&&target!="REJECT"&&target!="LOG"){
                if(target!~/^[a-zA-Z0-9_][a-zA-Z0-9_-]*$/||length(target)>28)bad()
                if(!prior[target]++)print target
            }
        }
    }else if(mode=="passthrough"){
        target=current_target()
        if(target!="DROP"&&target!="REJECT"&&target!="LOG"&&target!="RETURN")bad()
    }else if(mode=="destreject"){
        if(!dest_rule())bad();matches++
    }else if(mode=="reject"){
        if(!reject_rule())bad();matches++
    }else bad()
}
END{
    if(failed)exit 2
    if(mode=="parent"){if(hooks!=1)exit 2}
    else if(mode=="native"){if(matches!=1)exit 2;print result}
    else if(mode=="prefix"){if(matches!=1)exit 2}
    else if(mode=="passthrough"){}
    else if(mode=="reject"){if(!matches||!terminal)exit 2}
    else if(mode=="destreject"){if(!matches||nw<1)exit 2;for(wi in wanmember)if(!allwan&&!covered[wi])exit 2}
    else exit 2
}
