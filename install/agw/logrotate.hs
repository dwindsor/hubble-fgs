/data/volatile/logs/*.log {
        size 512M
	missingok
        rotate 20
	compress
	notifempty
	create 644 root root
}
