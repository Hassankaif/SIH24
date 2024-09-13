awk '/^ *-w/ \
&&/\/etc\/sudoers/ \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
#output matches:
#-w /etc/sudoers -p wa -k scope
#-w /etc/sudoers.d -p wa -k scope

auditctl -l | awk '/^ *-w/ \
&&/\/etc\/sudoers/ \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
#output matches:
#-w /etc/sudoers -p wa -k scope
#-w /etc/sudoers.d -p wa -k scope


