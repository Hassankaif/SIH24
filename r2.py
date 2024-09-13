a='/etc/cron.daily/aide:aide --config="${CONFIG}" $AIDEARGS "--$COMMAND" >|"$ARUNLOG" 2>|"$AERRLOG" && ARETVAL="$?"'
b=a.split(' ')
for i in b:
    print(i)
    print('\n')