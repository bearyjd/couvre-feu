# Strict, bounded JSON parser and v1 policy schema. POSIX awk; no eval.
# Strings deliberately permit ASCII without escapes only; policy values need none.
function bad(m) { print "invalid_policy: " m > "/dev/stderr"; failed=1; exit 2 }
function ws() { while (substr(src,pos,1) ~ /[ \t\r\n]/ && pos <= length(src)) pos++ }
function str(    c,out) {
    if (substr(src,pos++,1) != "\"") bad("expected string")
    out=""
    while (pos <= length(src)) {
        c=substr(src,pos++,1)
        if (c == "\"") return out
        if (c == "\\" || c !~ /^[ -~]$/) bad("escaped or non-ASCII string")
        out=out c
        if (length(out)>128) bad("string too long")
    }
    bad("unterminated string")
}
function value(p,d,    c,k,q,n,s) {
    if (d>12 || ++nodes>8192) bad("complexity limit")
    ws(); c=substr(src,pos,1)
    if (c=="{") {
        typ[p]="object"; pos++; ws()
        if (substr(src,pos,1)=="}") {pos++; return}
        for (;;) {
            ws(); k=str(); q=p "/" k
            if (k !~ /^[a-z][a-z0-9_]*$/ || seen[q]++) bad("duplicate or unsupported key")
            keys[p]=keys[p] " " k; count[p]++; ws()
            if (substr(src,pos++,1)!=":") bad("expected colon")
            value(q,d+1); ws(); c=substr(src,pos++,1)
            if (c=="}") return
            if (c!=",") bad("expected object comma")
        }
    }
    if (c=="[") {
        typ[p]="array"; pos++; ws()
        if (substr(src,pos,1)=="]") {pos++; return}
        for (;;) {
            value(p "/" (count[p]+0),d+1); count[p]++; ws(); c=substr(src,pos++,1)
            if (c=="]") return
            if (c!=",") bad("expected array comma")
        }
    }
    if (c=="\"") {typ[p]="string"; val[p]=str(); return}
    s=substr(src,pos)
    if (match(s,/^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/)) {
        typ[p]="number"; val[p]=substr(s,1,RLENGTH); pos+=RLENGTH; return
    }
    if (substr(s,1,4)=="true" || substr(s,1,4)=="null") {typ[p]=substr(s,1,4);pos+=4;return}
    if (substr(s,1,5)=="false") {typ[p]="false";pos+=5;return}
    bad("invalid JSON token")
}
function object(p,allowed,required,    a,n,i,k) {
    if (typ[p]!="object") bad("expected object at " p)
    n=split(keys[p],a," ")
    for(i=1;i<=n;i++) if(a[i]!="" && index(" " allowed " "," " a[i] " ")==0) bad("unknown field")
    n=split(required,a," ")
    for(i=1;i<=n;i++) if(a[i]!="" && !seen[p "/" a[i]]) bad("missing field " a[i])
}
function array(p,limit) {if(typ[p]!="array" || count[p]>limit) bad("array limit/type")}
function text(p) {if(typ[p]!="string") bad("string type");return val[p]}
function integer(p,max) {if(typ[p]!="number" || val[p]!~/^(0|[1-9][0-9]*)$/ || length(val[p])>10 || val[p]+0>max)bad("integer bound/type");return val[p]}
function ident(p,    s) {s=text(p);if(s!~/^[a-z][a-z0-9_]*$/ || length(s)>32)bad("identifier");return s}
function macok(s,    a,n,i,h) {
    if(length(s)!=17)return 0
    n=split(s,a,":");if(n!=6)return 0
    for(i=1;i<=6;i++)if(a[i]!~/^[0-9a-f][0-9a-f]$/)return 0
    h=substr(a[1],2,1);if(index("02468ace",h)==0)return 0
    return s!="00:00:00:00:00:00"
}
function ipv4(s,    a,n,i) {
    n=split(s,a,".");if(n!=4)return 0
    for(i=1;i<=4;i++)if(a[i]!~/^(0|[1-9][0-9]*)$/ || length(a[i])>3 || a[i]+0>255)return 0
    return 1
}
function ipv6(s,    a,b,n,i,t,compressed) {
    if(s!~/^[0-9a-f:]+$/ || length(s)>39 || index(s,":::") || index(s,":")==0)return 0
    compressed=index(s,"::")
    if(compressed) {t=substr(s,compressed+2);if(index(t,"::"))return 0}
    if((substr(s,1,1)==":" && substr(s,1,2)!="::") || (substr(s,length(s),1)==":" && substr(s,length(s)-1,2)!="::"))return 0
    n=split(s,a,":"); t=0
    for(i=1;i<=n;i++)if(a[i]!="") {if(length(a[i])>4)return 0;t++}
    return compressed ? t<8 : t==8
}
function canon6(s,    a,b,n,i,j,k,t,m,beg,len,out) {
    k=index(s,"::")
    if(k) {
        t=substr(s,1,k-1);n=split(t,a,":");if(t=="")n=0
        t=substr(s,k+2);m=split(t,b,":");if(t=="")m=0
        for(i=1;i<=m;i++)a[8-m+i]=b[i]
        for(i=n+1;i<=8-m;i++)a[i]="0"
    } else split(s,a,":")
    for(i=1;i<=8;i++){sub(/^0+/,"",a[i]);if(a[i]=="")a[i]="0"}
    m=0
    for(i=1;i<=8;i++)if(a[i]=="0"){j=i;while(j<=8&&a[j]=="0")j++;if(j-i>m){m=j-i;beg=i}i=j-1}
    if(m<2)beg=0
    out=""
    for(i=1;i<=8;i++) {
        if(i==beg){out=out "::";i+=m-1;continue}
        if(out!=""&&substr(out,length(out),1)!=":")out=out ":"
        out=out a[i]
    }
    return out
}
function clock(p,    s,h,m) {s=text(p);if(s!~/^[0-9][0-9]:[0-9][0-9]$/)bad("clock format");h=substr(s,1,2)+0;m=substr(s,4,2)+0;if(h>23||m>59)bad("clock range");return s}
function validate(root,    i,j,p,q,id,m,sid,days,d,n,a,start,stop,u,s,sep) {
    object(root,"version revision people pauses schedules doh","version revision people pauses schedules")
    if(integer(root "/version",1)!=1)bad("version")
    rev=integer(root "/revision",2147483647)
    array(root "/people",64)
    for(i=0;i<count[root "/people"];i++) {
        p=root "/people/" i;object(p,"id macs","id macs");id=ident(p "/id")
        if(person[id]++)bad("duplicate person")
        array(p "/macs",32); personmac[id]=count[p "/macs"]
        if(count[p "/macs"]==0)out[++outn]="P\t" id "\t-"
        for(j=0;j<count[p "/macs"];j++) {m=text(p "/macs/" j);if(!macok(m)||owner[m]++)bad("invalid/shared MAC");if(++macn>256)bad("MAC limit");out[++outn]="P\t" id "\t" m}
    }
    array(root "/pauses",64)
    for(i=0;i<count[root "/pauses"];i++) {p=root "/pauses/" i;object(p,"person until","person until");id=ident(p "/person");if(!person[id]||paused[id]++)bad("undefined/duplicate pause");u=integer(p "/until",2147483647);out[++outn]="A\t" id "\t" u}
    array(root "/schedules",256)
    for(i=0;i<count[root "/schedules"];i++) {
        p=root "/schedules/" i;object(p,"person id weekdays start stop","person id weekdays start stop");id=ident(p "/person");sid=ident(p "/id")
        if(!person[id]||schedule[id "/" sid]++)bad("undefined/duplicate schedule")
        start=clock(p "/start");stop=clock(p "/stop");if(start==stop)bad("empty schedule")
        q=p "/weekdays";array(q,7);if(!count[q])bad("empty weekdays");days=""
        for(j=0;j<count[q];j++) {d=text(q "/" j);if(index(",Mon,Tue,Wed,Thu,Fri,Sat,Sun,","," d ",")==0 || weekday[p "/" d]++)bad("weekday")}
        n=split("Mon Tue Wed Thu Fri Sat Sun",a," ");for(j=1;j<=n;j++)if(weekday[p "/" a[j]]){sep="";if(days!="")sep=",";days=days sep a[j]}
        expanded+=personmac[id]*(start>stop&&stop!="00:00"?2:1);if(expanded>256)bad("expanded schedule limit")
        out[++outn]="S\t" id "\t" sid "\t" days "\t" start "\t" stop
    }
    if(seen[root "/doh"]) {
        p=root "/doh";object(p,"ipv4 ipv6","ipv4 ipv6");array(p "/ipv4",256);array(p "/ipv6",256)
        for(i=0;i<count[p "/ipv4"];i++){s=text(p "/ipv4/" i);if(!ipv4(s)||doh4[s]++)bad("IPv4 address");out[++outn]="D4\t" s}
        for(i=0;i<count[p "/ipv6"];i++){s=text(p "/ipv6/" i);if(!ipv6(s))bad("IPv6 address");s=canon6(s);if(doh6[s]++)bad("duplicate IPv6 address");out[++outn]="D6\t" s}
    }
    print "V\t1";print "R\t" rev
    for(i=1;i<=outn;i++)print out[i]
}
{ if(length(src)+length($0)+1>65536)bad("input limit");src=src $0 "\n" }
END {if(!failed){pos=1;value("$",0);ws();if(pos<=length(src))bad("trailing JSON");if(rpc){object("$","rpc_version generation operation_id expected_revision expected_digest policy","rpc_version generation operation_id expected_revision expected_digest policy");if(integer("$/rpc_version",1)!=1)bad("RPC version");g=text("$/generation");id=text("$/operation_id");digest=text("$/expected_digest");base=integer("$/expected_revision",2147483647);if(length(g)!=64||g~/[^0-9a-f]/||length(digest)!=64||digest~/[^0-9a-f]/||id!~/^[a-z0-9_-]+$/||id=="-"||length(id)>64)bad("RPC identity");if(base==2147483647||integer("$/policy/revision",2147483647)!=base+1)bad("RPC revision");print "Q\t" g "\t" id "\t" base "\t" digest;validate("$/policy")}else validate("$")}}
