{
awk '/^ *-a *always,exit/ \
&&/ -F *arch=b(32|64)/ \
&&/ -S/ \
&&(/adjtimex/ \
||/settimeofday/ \
||/clock_settime/ ) \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
awk '/^ *-w/ \
&&/\/etc\/localtime/ \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
}
#OUTPUT
#-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
#-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
#-w /etc/localtime -p wa -k time-change

{
auditctl -l | awk '/^ *-a *always,exit/ \
&&/ -F *arch=b(32|64)/ \
&&/ -S/ \
&&(/adjtimex/ \
||/settimeofday/ \
||/clock_settime/ ) \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
auditctl -l | awk '/^ *-w/ \
&&/\/etc\/localtime/ \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
}
#OUTPUT
#-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -F key=time-change
#-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -F key=time-change
#-w /etc/localtime -p wa -k time-change
