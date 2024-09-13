awk '/^ *-w/ \
&&(/\/var\/log\/lastlog/ \
||/\/var\/run\/faillock/) \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
#output matches:
#-w /var/log/lastlog -p wa -k logins
#-w /var/run/faillock -p wa -k logins


auditctl -l | awk '/^ *-w/ \
&&(/\/var\/log\/lastlog/ \
||/\/var\/run\/faillock/) \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
#output matches:
#-w /var/log/lastlog -p wa -k logins
#-w /var/run/faillock -p wa -k logins
