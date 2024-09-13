awk '/^ *-w/ \
&&(/\/var\/run\/utmp/ \
||/\/var\/log\/wtmp/ \
||/\/var\/log\/btmp/) \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules

#output matches:
#-w /var/run/utmp -p wa -k session
#-w /var/log/wtmp -p wa -k session
#-w /var/log/btmp -p wa -k session


auditctl -l | awk '/^ *-w/ \
&&(/\/var\/run\/utmp/ \
||/\/var\/log\/wtmp/ \
||/\/var\/log\/btmp/) \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'

#output matches:
#-w /var/run/utmp -p wa -k session
#-w /var/log/wtmp -p wa -k session
#-w /var/log/btmp -p wa -k session
