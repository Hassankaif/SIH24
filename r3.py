Filesystem_Integrity={
    #6.1 Configure Filesystem Integrity Checking
    'file_integrity.sh':'Ensure filesystem integrity is regularly checked',
    'aide.sh': 'Ensure AIDE is installed',
    'crypt_mech': 'Ensure cryptographic mechanisms are used to protect the integrity of audit tools',
    
}
system_logging={
    # 6.2 Security principals for  system logging
    'systemd_journald.sh':'Configure systemd-journald service',
    'journald_forward.sh':'Ensure journald ForwardToSyslog is disabled',
    'journald_storage.sh':'Ensure journald Storage is configured (Automated)',
    'journald_Compress.sh':'Ensure journald Compress is configured (Automated)',
    'systemd_journal_upload.sh':'Ensure systemd-journal-upload is enabled and active',
    'systemd_journal_remote_service.sh':'Ensure systemd-journal-remote service is not in use',
    'journald_service.sh':'Ensure journald service is enabled and active',
}
auditd_Service={   
    # 6.3 System Auditing
    # 6.3.1 Configure auditd Service
    '6.3.1.1.sh':'Ensure auditd packages are installed',
    '6.3.1.2.sh':' Ensure auditd service is enabled and active',
    '6.3.1.3.sh':'Ensure auditing for processes that start prior to auditd is enabled',
    '6.3.1.4.sh':'Ensure audit_backlog_limit is sufficient',
    '6.3.2.1.sh':'Ensure audit log storage size is configured',
    '6.3.2.2.sh':'Ensure audit logs are not automatically deleted',
    '6.3.2.3.sh':'Ensure system is disabled when audit logs are full',
    '6.3.2.4.sh':'Ensure system warns when audit logs are low on space',
}
Data_Retention={    
    #6.3.2 Configure Data Retention
    '6.3.2.1.sh': 'Ensure audit log storage size is configured',
    '6.3.2.2.sh':'Ensure audit logs are not automatically deleted',
    '6.3.2.3.sh':'Ensure system is disabled when audit logs are full',
    '6.3.2.4.sh':'Ensure system warns when audit logs are low on space',
}

auditd_Rules={    
    #6.3.3 Configure auditd Rules
    '6.3.3.1.sh':'Ensure changes to system administration scope (sudoers) is collected',
    '6.3.3.2.sh':'Ensure actions as another user are always logged',
    '6.3.3.3.sh':'Ensure events that modify the sudo log file are collected',
    '6.3.3.4.sh':'Ensure events that modify date and time information are collected',
    '6.3.3.5.sh':'Ensure events that modify the systems network environment are collected',
    '6.3.3.6.sh':'Ensure use of privileged commands are collected',
    '6.3.3.7.sh':'Ensure unsuccessful file access attempts are collected',
    '6.3.3.8.sh':'Ensure events that modify user/group information are collected',
    '6.3.3.9.sh':'Ensure discretionary access control permission modification events are collected',
    '6.3.3.10.sh':'Ensure successful file system mounts are collected',
    '6.3.3.11.sh':'Ensure session initiation information is collected',
    '6.3.3.11.sh':'Ensure session initiation information is collected',
    '6.3.3.13.sh':'Ensure file deletion events by users are collected',
    '6.3.3.14.sh':'Ensure events that modify the systems Mandatory Access Controls are collected',
    '6.3.3.15.sh':'Ensure successful and unsuccessful attempts to use the chcon command are recorded',
    '6.3.3.16.sh':'Ensure successful and unsuccessful attempts to use the setfacl command are recorded',
    '6.3.3.17.sh':'Ensure successful and unsuccessful attempts to use the chacl command are recorded',
    '6.3.3.18.sh':'Ensure successful and unsuccessful attempts to use the usermod command are recorded',
    '6.3.3.19.sh':'Ensure kernel module loading unloading and modification is collected',
    '6.3.3.20.sh':'Ensure the audit configuration is immutable',
    '6.3.3.21.sh':'Ensure the running and on disk configuration is the same',
}
 auditd_File_Access={   
    #6.3.4 Configure auditd File Access
    'AuditModeTools.sh': 'Ensure audit tools mode is configured',
    'AuditOwnerTools.sh': 'Ensure audit tools owner is configured',
    'AuditToolsGroupOwner.sh': 'Ensure audit tools group owner is configured',
    'FileGroupOwner.sh': 'Ensure audit configuration files group owner is configured',
    'FileModes.sh': 'Ensure audit configuration files mode is configured',
    'FileOwners.sh': 'Ensure audit configuration files owner is configured',
    'LogFileDirectory.sh': 'Ensure the audit log file directory mode is configured',
    'LogFileModes.sh': 'Ensure audit log files mode is configured',
    'LogFilesGroupOwner.sh': 'Ensure audit log files group owner is configured',
    'LogFilesOwners.sh': 'Ensure audit log files owner is configured'

}