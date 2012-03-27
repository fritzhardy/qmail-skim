#!/usr/bin/perl
# qmail-skim.pl
# Jan 7, 2012 7:52:11 PM
# jeff hardy (hardyjm at potsdam dot edu)
# qmail-skim.pl is designed to skim through mails looking for problems before re-injecting them
#
# easy to use with the qmailqueue patch
# for instance in tcp.smtp
# 127.:allow,RELAYCLIENT="",QMAILQUEUE="/opt/bin/qmail-skim.pl",QMAILSKIMCONF="/etc/qmail-skim-test.conf"
# :allow,RELAYCLIENT="",QMAILQUEUE="/opt/bin/qmail-skim.pl"

use strict;
use Email::Simple;
use Config::IniFiles;
use Time::TAI64 qw/:tai64n/;
use Geo::IP;

my $v_header = "X-Qmail-Skim";
my $qmail_inject = "/var/qmail/bin/qmail-inject";
my $qmail_queue = "/var/qmail/bin/qmail-queue";
my $qmail_logs = "/var/log/qmail/smtpd-ssl";

my $logtag = 'qmail-skim.pl';	#epoch2isotime();	#$headers{'Message-ID'};

# lest we loop infinitely
delete($ENV{QMAILQUEUE});

# get the data off of the file descriptors
my $message = get_message();
my $envelope = get_envelope();

# find our config
my $conf;
if ($ENV{QMAILSKIMCONF} && -e $ENV{QMAILSKIMCONF}) {
	warn "$logtag: reading configuration $ENV{QMAILSKIMCONF}\n";
	$conf = Config::IniFiles->new( -file => $ENV{QMAILSKIMCONF}, -nocase => 1 );
	warn "@Config::IniFiles::errors\n" if @Config::IniFiles::errors;
} elsif (-e '/etc/qmail-skim.conf') {
	warn "$logtag: reading configuration /etc/qmail-skim.conf\n";
	$conf = Config::IniFiles->new( -file => '/etc/qmail-skim.conf', -nocase => 1 );
	warn "@Config::IniFiles::errors\n" if @Config::IniFiles::errors;
} else {
	warn "$logtag: No configuration found, re-queuing with no checks\n";
	qmail_queue($envelope,$message);
	exit;
}

my $verbose = $conf->val('global','verbose');
my %checks_enabled; foreach (split(/,/,$conf->val('global','enable'))) { $checks_enabled{$_} = 1; }
my %checks_dryrun; foreach (split(/,/,$conf->val('global','dryrun'))) { $checks_dryrun{$_} = 1; }

main: {
	# breakdown the message
	my $email = Email::Simple->new($message);
	my %headers = $email->header_pairs();
	my $body = $email->body();
	
	# breakdown the envelope
	my ($mailfrom,$rcptto) = parse_envelope($envelope);
	
	# debug
	if ($verbose > 1) {
		debug(\%headers);
	}
	
	warn "$logtag: authuser: ".$ENV{SMTP_AUTH_USER}."\n";
	warn "$logtag: mailfrom: $mailfrom\n";
	#warn "$logtag: rcpttos: $rcptto\n";
	#warn "$logtag: from: ".$email->header("From")."\n";
	
	# run checks
	check_phishhook($ENV{SMTP_AUTH_USER}) if $checks_enabled{phishhook};
	check_phishfrom($mailfrom,$rcptto,$email->header("from")) if $checks_enabled{phishfrom};
	check_envelope($mailfrom,$rcptto) if ($checks_enabled{envelope});
	check_headers(\%headers) if ($checks_enabled{headers});
	check_body($body) if ($checks_enabled{body});
	
	# queue it up
	#qmail_inject($mailfrom,$rcptto,$message);
	qmail_queue($envelope,$message);
}

# Local log and exit
sub bail {
	# 31: 554 mail server permanently rejected message (#5.3.0)
	# 111: 451 qq temporary problem (#4.3.0)
	my ($msg,$err) = @_;
	$err = 111 if !$err;
	warn $msg;
	exit $err;
}

# Check body against the config
sub check_body {
	my ($body) = @_;
	my @b_checks = $conf->val('body','body');
	warn "$logtag: checking body\n" if $verbose;
	foreach my $bchk (@b_checks) {		# iterate over checks
		$bchk =~ s/^\~//;
		warn "$logtag:\t$bchk\n" if $verbose > 1;
		if ($body =~ m/$bchk/) {
			if ($checks_dryrun{body}) {
				warn "$logtag: DRYRUN BLOCK body =~ $bchk (#5.3.0)\n";
			} else {
				bail("$logtag: BLOCK body =~ $bchk (#5.3.0)\n",111);
			}
		}
	}
}

# Check envelope sender (mail from) and recipients (rcppto) against config
sub check_envelope {
	my ($mailfrom,$rcptto) = @_;
	# mailfrom
	my @mf_checks = $conf->val('envelope','mailfrom');
	warn "$logtag: checking envelope mailfrom $mailfrom\n" if $verbose;
	foreach my $mfchk (@mf_checks) {
		warn "$logtag:\t$mfchk\n" if $verbose > 1;
		if ($mfchk =~ s/^\~//) {
			if ($mailfrom =~ m/$mfchk/) {
				if ($checks_dryrun{envelope}) {
					warn "$logtag: DRYRUN BLOCK envelope mailfrom $mailfrom =~ $mfchk (#4.3.0)\n";	
				} else {
					bail("$logtag: BLOCK envelope mailfrom $mailfrom =~ $mfchk (#4.3.0)\n",111);
				}
			}
		}
		else {
			if ($mailfrom eq $mfchk) {
				if ($checks_dryrun{envelope}) {
					warn "$logtag: DRYRUN BLOCK envelope mailfrom $mailfrom == $mfchk (#4.3.0)\n";
				} else {
					bail("$logtag: BLOCK envelope mailfrom $mailfrom == $mfchk (#4.3.0)\n",111);
				}
			}	
		}
	}
	# rcpttos require care because we could drop legit mail
	# best thing to do is remove them from the rcptto list
	#warn "checking envelope rcptto $rcptto\n" if $verbose;
}

# Check headers against the config.
# Array iteration on each header config is a scalability problem.
sub check_headers {
	my ($eheaders) = @_;
	foreach my $eheader (keys(%$eheaders)) {	# headers from email
		my @eheadervals = @$eheaders{$eheader};	# multiple instances of header, such as received
		if ($conf->val('headers',$eheader)) {	# header checks from conf
			my @h_checks = $conf->val('headers',$eheader);
			foreach my $hchk (@h_checks) {		# iterate over checks
				if ($hchk =~ s/^\~//) {			# is regex check
					foreach my $ehval (@eheadervals) {	# iterate over all of the header instances values
						warn "$logtag: checking header $eheader $ehval\n" if $verbose;
						warn "$logtag:\t\~$hchk\n" if $verbose > 1;
						if ($ehval =~ m/$hchk/) {
							if ($checks_dryrun{headers}) {
								warn "$logtag: DRYRUN BLOCK header $eheader $ehval =~ $hchk (#5.3.0)\n";
							} else {
								bail("$logtag: BLOCK header $eheader $ehval =~ $hchk (#5.3.0)\n",111);
							}
						}
					}
				}
				else {
					foreach my $ehval (@eheadervals) {	# iterate over all of the header instances values
						warn "$logtag: checking header $eheader $ehval\n" if $verbose;
						warn "$logtag:\t$hchk\n" if $verbose > 1;
						if ($ehval eq $hchk) {
							if ($checks_dryrun{headers}) {
								warn "$logtag: DRYRUN BLOCK header $eheader $ehval == $hchk (#5.3.0)\n";
							} else {
								bail("$logtag: BLOCK header $eheader $ehval == $hchk (#5.3.0)\n",111);
							}
						}
					}
				}
			}
		}
	}	
}

# Phishhook check analyzing envelope sender, from header, number of envelope recipients
sub check_phishfrom {
	my ($mailfrom,$rcptto,$from) = @_;
	my $numrcpttos = scalar(split(/,/,$rcptto));
	warn "$logtag: checking phishfrom envelope sender $mailfrom from $from to $numrcpttos recipients\n" if $verbose;
	if (($mailfrom ne $from) && ($numrcpttos > $conf->val('phishfrom','maxrcptto'))) {
		if ($checks_dryrun{phishfrom}) {
			warn "$logtag: DRYRUN BLOCK phishfrom envelope sender $mailfrom not equal $from and greater than ".$conf->val('phishfrom','maxrcptto')." recipients\n";
		} else {
			bail("$logtag: BLOCK phishfrom envelope sender $mailfrom not equal $from and greater than ".$conf->val('phishfrom','maxrcptto')." recipients\n",111);
		}
	}
}

# Phishhook check analyzing country and time of last login
sub check_phishhook {
	my ($user) = @_;
	if (!$user) { return; }

	warn "$logtag: phishhook check authuser $user\n" if $verbose;

	my %safe_countries;
	foreach (split(',',$conf->val('phishhook','safe_countries'))) {
		$safe_countries{$_} = 1;	
	}

	my ($this_log,$last_log) = mine_smtp_auth_log($user);
	my $geoip = Geo::IP->new(GEOIP_STANDARD);	
	
	# last log
	my ($last_tai,$last_ip) = split(/\s+/,$last_log);
	my $last_gentime = tai64nlocal($last_tai);
	my $last_unixtime = tai64nunix($last_tai);
	my $last_country = $geoip->country_code_by_addr($last_ip);
	
	# this log
	my ($this_tai,$this_ip) = split(/\s+/,$this_log);
	my $this_gentime = tai64nlocal($this_tai);
	my $this_unixtime = tai64nunix($this_tai);
	my $this_country = $geoip->country_code_by_addr($this_ip);
	
	my $hours_diff = ($this_unixtime - $last_unixtime)/60/60;
	
	if ($verbose) {
		warn "$logtag: last_login = $last_tai $last_gentime $last_unixtime $last_ip $last_country\n";
		warn "$logtag: this_login = $this_tai $this_gentime $this_unixtime $this_ip $this_country\n";
		warn "$logtag: hours_diff = $hours_diff\n";
	}
	
	# phish logic
	
	# Haven't met a domestic (US,CA,etc) phisher yet
	if (exists($safe_countries{$this_country})) {
		warn "$logtag: phishhook user $user this country $this_country is safe, passed\n" if ($verbose > 1);
		return;
	}

	# We don't have a prior login, so we're good
	if (!$last_country) {
		warn "$logtag: phishhook user $user has no prior login, passed\n" if ($verbose > 1);
		return;
	}
	
	# Didn't start here (US,CA,etc), probably on vacation
	if (!exists($safe_countries{$last_country})) {
		warn "$logtag: phishhook user $user last country $last_country is safe, passed\n" if ($verbose > 1);
		return;
	}
	
	# No hop, we're good
	if ($last_country eq $this_country) {
		warn "$logtag: phishhook user $user last_country $last_country eq this_country $this_country, passed\n" if ($verbose > 1);
		return;
	}
	
	# Far enough time between hops, we're good
	my $hours_min = $conf->val('phishhook','hours_min');
	if ($hours_diff > $hours_min) {
		warn "$logtag: phishhook user $user hours_diff $hours_diff > hours_min $hours_min, passed\n" if ($verbose > 1);
		return;
	}
	
	#If we get here: 
	#  - the user is not in the US,
	#  - the user has logged in in recent history, 
	#  - the user is in a different country than they were last in,
	#  - it has been less than the specified hours since the user was in the last country
	# 
	# We want to:
	#  - run a perl script that will
	#   + Create a ticket
	#   + FWBLACKLIST the current IP address
	#   + Scramble their password
	#   + Add them to the 'phish' group
	#  - block this session
	
	if ($checks_dryrun{phishhook}) {
		warn "$logtag: DRYRUN BLOCK phishook user $user for country-hopping from $last_ip ($last_country) to $this_ip ($this_country) in $hours_diff (#5.3.0)\n";
	} else {
		# snag the user
		#system("/opt/bin/phishhook_snag.pl $username $ip $parts[0] $parts[1] $parts[3] $lastcountry");
		bail("$logtag: BLOCK phishook user $user for country-hopping from $last_ip ($last_country) to $this_ip ($this_country) in $hours_diff (#5.3.0)\n",111);
	}
}

# Debug to STDERR
sub debug {
	my ($headers) = @_;
	#open (OUT,">>/tmp/qmail-skim.debug") or die "Cannot write /tmp/qmail-skim.debug: $!\n";
	#print OUT "=== ".localtime(time())." ===\n";
	my $i=0;
	foreach (@ARGV) {
		warn "$logtag: DEBUG: $i: $_\n";
		$i++;
	}
	foreach (sort(keys(%ENV))) {
		warn "$logtag: DEBUG: $_: $ENV{$_}\n";
	}
	foreach my $s ($conf->Sections) {
		warn "$logtag: DEBUG: [$s]\n";
		foreach my $p ($conf->Parameters($s)) {
			my @vals = $conf->val($s,$p);	# assume all are multivalue
			foreach (@vals) {
				warn "$logtag: DEBUG:\t$p=$_\n";
			}
		}
	}
	
	foreach (keys(%$headers)) {
		warn "$logtag: DEBUG: $_: $$headers{$_}\n";
	}
	my $env = $envelope;
	$env =~ s/\0/\\0/g;	# convert nulls to printable string for debugging
	warn "$logtag: DEBUG: FD1: $env\n";
	warn "$logtag: DEBUG: FD0:\n$message\n" if $verbose > 2;
	#close (OUT);
}

# Gentime with a T
sub epoch2isotime {
	my $epoch = shift;
	
	my @zero_duo = ('00' .. '99');
	my @zero_trio = ('000' .. '999');
	my @zero_quad = ('0000' .. '9999');
	
	# If no epoch is specified, assume the current
	unless($epoch) { $epoch = time; } 
	
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($epoch);
		
	$year = $year + 1900;
	$mon = $mon + 1;

	foreach ($mon,$mday,$hour,$min,$sec) {
		$_ = $zero_duo[$_];
	}
	return "$year-$mon-$mday"."T"."$hour:$min:$sec";
}

# Qmail-queue  reads  a mail message from descriptor 0.
# It then reads envelope information from descriptor 1.
sub get_envelope {
	my $envelope;
	select(STDOUT); $|=1;
	open(SOUT,"<&1") or die "$logtag: cannot dup fd 0: $!\n";
	while (<SOUT>) {
		$envelope .= $_;
		last;	#only meant to be one line!
	}
	close(SOUT) or die "$logtag: cannot close fd 1: $!\n";
	return $envelope;
}

# Qmail-queue  reads  a mail message from descriptor 0.
# It then reads envelope information from descriptor 1.
sub get_message {
	undef $/;
	my $message = <STDIN>;
	$/ = "\n";
	return $message;
}

# Parse qmail logs looking for last smtp-auth login by 
# given username, returning ip address and timestamp
sub mine_smtp_auth_log {
	my ($user) = @_;
	my @logins;
	# parse the current log
	if (-e "$qmail_logs/current") {
		warn "$logtag: parsing log $qmail_logs/current\n" if ($verbose > 1);
		open (LOG,"$qmail_logs/current") or die "$logtag: cannot open $qmail_logs/current: $!\n";
		while (<LOG>) {
			# @400000004f6769fb232759fc qmail-smtpd[713]: AUTH successful [137.143.102.113] xhardy1
			if (m/(\S+) qmail-smtpd.*AUTH successful \[(\S+)\] $user/) {
				push (@logins,"$1 $2");
				warn "$logtag: $1 $2\n" if ($verbose > 2);
			}
		}
		close (LOG);
	}
	# parse the first historical log, as we may lack login info if it rolled
	if (scalar(@logins) < 2) {
		my @logs;
		opendir (LOGD,"$qmail_logs") or die "$logtag: cannot opendir $qmail_logs: $!\n";
		while (my $l = readdir(LOGD)) {
			if ($l =~ m/^@/) {	# @400000004f67d6612991d2a4.s
				warn "$logtag: found log $qmail_logs/$l\n" if ($verbose > 2);
				push (@logs,$l);
			}
		}
		closedir (LOGD);
		@logs = sort(@logs);
		
		my $l = pop(@logs);	# just the last one
		warn "$logtag: parsing log $qmail_logs/$l\n" if ($verbose > 1);
		open (LOG,"$qmail_logs/$l") or die "$logtag: cannot open $qmail_logs/$l: $!\n";
		while (<LOG>) {
			# @400000004f6769fb232759fc qmail-smtpd[713]: AUTH successful [137.143.102.113] xhardy1
			if (m/(\S+) qmail-smtpd.*AUTH successful \[(\S+)\] $user/) {
				push (@logins,"$1 $2");
				warn "$logtag: $1 $2\n" if ($verbose > 2);
			}
		}
		close (LOG);
	}
	
	my $this_login = pop(@logins);	# our login is already logged
	my $last_login = pop(@logins);
	return ($this_login,$last_login);
}

# The envelope information is an envelope  sender  address  fol-
# lowed  by  a list of envelope recipient addresses.  The sender
# address is preceded by the letter F  and  terminated  by  a  0
# byte.   Each recipient address is preceded by the letter T and
# terminated by a 0 byte.  The list of  recipient  addresses  is
# terminated  by  an  extra 0 byte.  We return both as csv lists.
sub parse_envelope {
	my ($envelope) = (@_);
	my ($env_mailfrom,$env_rcptto) = split(/\0/,$envelope,2);
	
	my $mailfrom = $env_mailfrom;
	if ($mailfrom =~ m/^F(.*)$/) {
		$mailfrom = $1;
	}
	
	my $rcptto = $env_rcptto;
	if ($rcptto =~ m/^T(.*)\0$/) {	# nix the trailing extra null here
		$rcptto = $1;
		$rcptto =~ s/\0T/\,/g;
	}
	
	return ($mailfrom,$rcptto);
}

# Qmail-inject the message.  We pass -f and -A so we can ensure we send from 
# and to the proper envelope sender and recipients.  This is the easiest way to 
# get mail into the queue, but probably not ideal, as headers are re-written.
sub qmail_inject {
	my ($mailfrom,$rcptto,$msg) = @_;
	
	warn "$logtag: Injecting message using $qmail_inject\n" if $verbose;
	
	my @rcptto = split(/,/,$rcptto);
	open (INJ,"| $qmail_inject -f$mailfrom -A @rcptto") or die "$logtag: Cannot open qmail-inject: $!\n";
	local $SIG{PIPE} = sub { die "inject pipe broke" };
	print INJ $msg;	
	close (INJ) or die "$logtag: Bad pipe: $! $?\n";
}

# Qmail-queue the message.  Qmail-queue  reads  a mail message from descriptor 
# 0.  It then reads envelope information from descriptor 1.  This is the purest 
# way to send the message on its way, as we took the place of qmail-queue.
# Thank you to qmail-scanner-queue.pl for the core of this.
sub qmail_queue {
	my ($envelope,$message) = @_;

	warn "$logtag: Fork off child into $qmail_queue\n" if $verbose;
	
	# Create a pipe through which to send the envelope addresses.
	pipe (EOUT, EIN) or bail("$logtag: Unable to create envelope pipe: $!\n");
	select(EOUT);$|=1;
	select(EIN);$|=1;
	
#	pipe (MOUT, MIN) or bail ("$logtag: Unable to create message pipe - $!\n");
#	select(MOUT);$|=1;
#	select(MIN);$|=1;
	
	# Fork qmail-queue.  The qmail-queue child will then open fd 0 as
	# $message and fd 1 as the reading end of the envelope pipe and exec
	# qmail-queue.  The parent will read in the addresses and pass them 
	# through the pipe and then check the exit status.
	local $SIG{PIPE} = 'IGNORE';
	my $exitval;
	my $pid = fork;
	if (not defined $pid) {
    	bail("$logtag: Unable to fork (#4.3.0): $!\n");
	}
	elsif ($pid == 0) {
		# In child.  Mutilate our file handles.
		close EIN;

		#open(STDIN,"<$message") or bail("$logtag: Unable to reopen fd 0 (#4.3.0): $!\n");
		open(STDOUT, "<&EOUT") or bail("$logtag: Unable to reopen fd 1 (#4.3.0): $!\n");
		
		#select(STDIN);$|=1;
		open(QMQ, "|$qmail_queue") or bail("$logtag: Unable to open pipe to $qmail_queue (#4.3.0): $!\n");
		#while (<STDIN>) {
			#print QMQ "$v_header: processed\n";
			print QMQ $message;
		#}
		close(QMQ);
		
		my $exitval = ( $? >> 8 );
		if ( $exitval > 10 && $exitval < 41 ) {
			bail("$logtag: Mail server permanently rejected message (#5.3.0): $!\n",$exitval);
		}
		elsif ($exitval > 0) {
			bail("$logtag: Unable to open pipe to $qmail_queue [$exitval] (#4.3.0): $!\n",$exitval);
		}
		#This child is finished - exit
		exit;
	}
	else {
		# In parent.
		close EOUT;

		# Feed the envelope addresses to qmail-queue.
		print EIN $envelope;
		close EIN or bail("$logtag: Write error to envelope pipe (#4.3.0): $!\n");
	}

	# We should now have queued the message.  Let's find out the exit status
	# of qmail-queue.
	waitpid ($pid, 0);
	$exitval = ($? >> 8);
	if ( $exitval > 10 && $exitval < 41 ) {
		bail("$logtag: Mail server permanently rejected message (#5.3.0): $!\n",$exitval);
	}
	elsif ($exitval > 0) {
    	bail("$logtag: Unable to close pipe to $qmail_queue [$exitval] (#4.3.0): $!\n",$exitval);
	}
}
