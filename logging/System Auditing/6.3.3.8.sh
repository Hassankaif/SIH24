awk '/^ *-w/ \
&&(/\/etc\/group/ \
||/\/etc\/passwd/ \
||/\/etc\/gshadow/ \
||/\/etc\/shadow/ \
||/\/etc\/security\/opasswd/ \
||/\/etc\/nsswitch.conf/ \
||/\/etc\/pam.conf/ \
||/\/etc\/pam.d/) \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
#output matches:
#-w /etc/group -p wa -k identity
#-w /etc/passwd -p wa -k identity
#-w /etc/gshadow -p wa -k identity
#-w /etc/shadow -p wa -k identity
#-w /etc/security/opasswd -p wa -k identity
#-w /etc/nsswitch.conf -p wa -k identity
#-w /etc/pam.conf -p wa -k identity
#-w /etc/pam.d -p wa -k identity

auditctl -l | awk '/^ *-w/ \
&&(/\/etc\/group/ \
||/\/etc\/passwd/ \
||/\/etc\/gshadow/ \
||/\/etc\/shadow/ \
||/\/etc\/security\/opasswd/ \
||/\/etc\/nsswitch.conf/ \
||/\/etc\/pam.conf/ \
||/\/etc\/pam.d/) \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'

#-w /etc/group -p wa -k identity
#-w /etc/passwd -p wa -k identity
#-w /etc/gshadow -p wa -k identity
#-w /etc/shadow -p wa -k identity
#-w /etc/security/opasswd -p wa -k identity
#-w /etc/nsswitch.conf -p wa -k identity
#-w /etc/pam.conf -p wa -k identity
#-w /etc/pam.d -p wa -k identity
