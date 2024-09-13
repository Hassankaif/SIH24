
awk '/^ *-a *always,exit/ \
&&/ -F *arch=b(32|64)/ \
&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \
&&(/ -C *euid!=uid/||/ -C *uid!=euid/) \
&&/ -S *execve/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
#-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k
#user_emulation
#-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k
#user_emulation

auditctl -l | awk '/^ *-a *always,exit/ \
&&/ -F *arch=b(32|64)/ \
&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \
&&(/ -C *euid!=uid/||/ -C *uid!=euid/) \
&&/ -S *execve/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'

#-a always,exit -F arch=b64 -S execve -C uid!=euid -F auid!=-1 -F
#key=user_emulation
#-a always,exit -F arch=b32 -S execve -C uid!=euid -F auid!=-1 -F
#key=user_emulation
