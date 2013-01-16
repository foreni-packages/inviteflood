#
# Regular cron jobs for the inviteflood package
#
0 4	* * *	root	[ -x /usr/bin/inviteflood_maintenance ] && /usr/bin/inviteflood_maintenance
