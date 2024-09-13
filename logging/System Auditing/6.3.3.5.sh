awk '/^ *-a *always,exit/ \
&&/ -F *arch=b(32|64)/ \
&&/ -S/ \
&&(/sethostname/ \
||/setdomainname/) \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules

awk '/^ *-w/ \
&&(/\/etc\/issue/ \
||/\/etc\/issue.net/ \
||/\/etc\/hosts/ \
||/\/etc\/network/ \
||/\/etc\/netplan/) \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
#OUTPUT
#-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
#-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
#-w /etc/issue -p wa -k system-locale
#-w /etc/issue.net -p wa -k system-locale
#-w /etc/hosts -p wa -k system-locale
#-w /etc/networks -p wa -k system-locale
#-w /etc/network -p wa -k system-locale
#-w /etc/netplan -p wa -k system-locale


auditctl -l | awk '/^ *-a *always,exit/ \
&&/ -F *arch=b(32|64)/ \
&&/ -S/ \
&&(/sethostname/ \
||/setdomainname/) \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
auditctl -l | awk '/^ *-w/ \
&&(/\/etc\/issue/ \
||/\/etc\/issue.net/ \
||/\/etc\/hosts/ \
||/\/etc\/network/ \
||/\/etc\/netplan/) \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
#OUTPUT
#-a always,exit -F arch=b64 -S sethostname,setdomainname -F key=system-locale
#-a always,exit -F arch=b32 -S sethostname,setdomainname -F key=system-locale
#-w /etc/issue -p wa -k system-locale
#-w /etc/issue.net -p wa -k system-locale
#-w /etc/hosts -p wa -k system-locale
#-w /etc/networks -p wa -k system-locale
#-w /etc/network -p wa -k system-locale
#-w /etc/netplan -p wa -k system-local
