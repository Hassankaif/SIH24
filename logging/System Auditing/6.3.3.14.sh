awk '/^ *-w/ \
&&(/\/etc\/apparmor/ \
||/\/etc\/apparmor.d/) \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
#Verify the output matches:
#-w /etc/apparmor/ -p wa -k MAC-policy
#-w /etc/apparmor.d/ -p wa -k MAC-policy

auditctl -l | awk '/^ *-w/ \
&&(/\/etc\/apparmor/ \
||/\/etc\/apparmor.d/) \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
#Verify the output matches:
#-w /etc/apparmor/ -p wa -k MAC-policy
#-w /etc/apparmor.d/ -p wa -k MAC-policy
