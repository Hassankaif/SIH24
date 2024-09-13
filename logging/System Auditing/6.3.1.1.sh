dpkg-query -s auditd &>/dev/null && echo auditd is installed
dpkg-query -s audispd-plugins &>/dev/null && echo audispd-plugins is installed

#OUTPUT (root)
#auditd is installed
#audispd-plugins is installed



#note: first install it using remedial code given below , then only the above output will be obtained
#apt install auditd audispd-plugins
