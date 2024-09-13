stat -Lc "%n %U" /usr/sbin/auditctl /usr/sbin/aureport /usr/sbin/ausearch /usr/sbin/autrace /usr/sbin/auditd /usr/sbin/augenrules | awk '$2 != "root" {print}'
#nothing should be returned

