systemctl is-enabled systemd-journal-remote.socket systemd-journal- remote.service | grep -P -- '^enabled'

#Nothing should be returned
