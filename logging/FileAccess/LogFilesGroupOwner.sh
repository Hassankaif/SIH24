grep -Piws -- '^\h*log_group\h*=\h*\H+\b' /etc/audit/auditd.conf | grep - Pvi -- '(adm)'

{
if [ -e /etc/audit/auditd.conf ]; then
l_fpath="$(dirname "$(awk -F "=" '/^\s*log_file/ {print $2}'
/etc/audit/auditd.conf | xargs)")"
find -L "$l_fpath" -not -path "$l_fpath"/lost+found -type f \( ! -group
root -a ! -group adm \) -exec ls -l {} +
fi
}

#nothing should be returned

