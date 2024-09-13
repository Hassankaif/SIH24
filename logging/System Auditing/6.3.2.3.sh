grep -Pi -- '^\h*disk_full_action\h*=\h*(halt|single)\b' /etc/audit/auditd.conf
grep -Pi -- '^\h*disk_error_action\h*=\h*(syslog|single|halt)\b' /etc/audit/auditd.conf



#disk_full_action = halt OR SINGLE
#disk_error_action = halt OR SINGLE OR SYSLOG
# NOTHING WILL BE RETURENED IF  parameters are either not present or not configured correctly 

