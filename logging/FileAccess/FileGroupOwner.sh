find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root

#nothing should be returned

