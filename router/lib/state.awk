# Validate metadata before extracting any policy. Policy schema is checked separately.
BEGIN {FS="\t"}
function bad(){failed=1;exit 2}
function hex(s){return length(s)==64 && s!~/[^0-9a-f]/}
function num(s){return s~/^(0|[1-9][0-9]*)$/ && length(s)<=10 && s+0<=2147483647}
function id(s){return length(s)>=1 && length(s)<=64 && s~/^[a-z0-9_-]+$/ && s!="-"}
$1=="X" {if(NF!=2||$2!="1"||x++)bad();next}
$1=="G" {if(NF!=2||!hex($2)||g++)bad();generation=$2;next}
$1=="C" {if(NF!=2||($2!="-"&&!id($2))||c++)bad();current=$2;next}
$1=="O" {if(NF!=7||!id($2)||!hex($3)||!num($4)||!hex($5)||!num($6)||!hex($7)||$4+1!=$6||seen[$2]++||++n>128)bad();history=history $0 "\n";next}
$1~/^(V|R|P|A|S|D4|D6)$/ {policy=policy $0 "\n";next}
{bad()}
END {if(failed)exit 2;if(x||g||c||n){if(x!=1||g!=1||c!=1||(current!="-"&&!seen[current]))exit 2;if(mode=="meta")printf "X\t1\nG\t%s\nC\t%s\n%s",generation,current,history}else if(mode=="meta")exit 0;if(mode!="meta")printf "%s",policy}
