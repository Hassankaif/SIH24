{
SUDO_LOG_FILE=$(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,?
.*//' -e 's/"//g' -e 's|/|\\/|g')
[ -n "${SUDO_LOG_FILE}" ] && awk "/^ *-w/ \
&&/"${SUDO_LOG_FILE}"/ \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules \
|| printf "ERROR: Variable 'SUDO_LOG_FILE' is unset.\n"
}
#-w /var/log/sudo.log -p wa -k sudo_log_file



{
SUDO_LOG_FILE=$(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,?
.*//' -e 's/"//g' -e 's|/|\\/|g')
[ -n "${SUDO_LOG_FILE}" ] && auditctl -l | awk "/^ *-w/ \
&&/"${SUDO_LOG_FILE}"/ \
&&/ +-p *wa/ \
&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" \
|| printf "ERROR: Variable 'SUDO_LOG_FILE' is unset.\n"
}
#-w /var/log/sudo.log -p wa -k sudo_log_file

