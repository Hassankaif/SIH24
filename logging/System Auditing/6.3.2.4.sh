grep -Pi -- '^\h*space_left_action\h*=\h*(email|exec|single|halt)\b' /etc/audit/auditd.conf
grep -Pi -- '^\h*admin_space_left_action\h*=\h*(single|halt)\b' /etc/audit/auditd.conf



#space_left_action = email/ exec/ single /halt ANYONE 
#admin_space_left_action = single /halt
# NOTHING WILL BE RETURENED IF  parameters are either not present or not configured correctly 

