#!/usr/bin/perl
# qmail-skim.pl
# Jan 7, 2012 7:52:11 PM
# jeff hardy (hardyjm at potsdam dot edu)
# qmail-skim.pl is designed to skim through mails looking for problems before re-injecting them
#
# example tcp.smtp on qmail with qmailqueue patch:
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
my $logtag = "qmail-skim.pl[$$]";	#epoch2isotime();	#$headers{'Message-ID'};

# log location by tcp port
my %qmail_logs = (
	25 => "/var/log/qmail/smtpd",
	465 => "/var/log/qmail/smtpd-ssl",
	587 => "/var/log/qmail/submission",
);
my $qmail_logs = $qmail_logs{$ENV{TCPLOCALPORT}};

my %checks_failed;	# store failed checks, list since dryrun can cause multiple fails
my %logsum;			# build a hash summary of all info bits

# lest we loop infinitely
delete($ENV{QMAILQUEUE});

# get the data off of the file descriptors
my $message = get_message();
my $envelope = get_envelope();

# find our config
my $conf;
if ($ENV{QMAILSKIMCONF} && -e $ENV{QMAILSKIMCONF}) {
	#$logsum{config} = $ENV{QMAILSKIMCONF};
	warn "$logtag: Reading configuration from $ENV{QMAILSKIMCONF}\n";
	$conf = Config::IniFiles->new( -file => $ENV{QMAILSKIMCONF}, -nocase => 1 );
	warn "@Config::IniFiles::errors\n" if @Config::IniFiles::errors;
} elsif (-e '/etc/qmail-skim.conf') {
	#$logsum{config} = '/etc/qmail-skim.conf';
	warn "$logtag: Reading configuration from /etc/qmail-skim.conf\n";
	$conf = Config::IniFiles->new( -file => '/etc/qmail-skim.conf', -nocase => 1 );
	warn "@Config::IniFiles::errors\n" if @Config::IniFiles::errors;
} else {
	warn "$logtag: No configuration found and no checks conducted\n";
	qmail_queue($envelope,$message);
	exit;
}

my $verbose = $conf->val('global','verbose');
my %checks_enabled; foreach (split(/,/,$conf->val('global','enable'))) { $checks_enabled{$_} = 1; }
my %checks_dryrun; foreach (split(/,/,$conf->val('global','dryrun'))) { $checks_dryrun{$_} = 1; }
#$logsum{checks} = $conf->val('global','enable');
#$logsum{dryrun} = $conf->val('global','dryrun');

main: {
	# breakdown the message
	my $email = Email::Simple->new($message);
	my @headers = $email->header_names();
	my $body = $email->body();
	
	# breakdown the envelope
	my ($mailfrom,$rcptto) = parse_envelope($envelope);
	
	# debug
	debug($email,\@headers) if $verbose > 2;
	
	# build log summary up front in case a check bails
	$logsum{authuser} = $ENV{SMTP_AUTH_USER} if $ENV{SMTP_AUTH_USER};
	$logsum{mailfrom} = $mailfrom;
	$logsum{rcptto} = scalar(split(/,/,$rcptto));
	$logsum{from} = $email->header("From");
	$logsum{from} =~ s/\s/_/g;
	
	# run checks and potentially produce more log summary hits
	check_phishhook($ENV{SMTP_AUTH_USER}) if $checks_enabled{phishhook};
	check_phishfrom($mailfrom,$rcptto,$email->header("from")) if $checks_enabled{phishfrom};
	check_ratelimit($mailfrom) if $checks_enabled{ratelimit};
	check_envelope($mailfrom,$rcptto) if ($checks_enabled{envelope});
	check_headers($email,\@headers) if ($checks_enabled{headers});
	check_body($body) if ($checks_enabled{body});
	
	# queue it up
	$logsum{fate} = 'pass';
	log_summary();
	#qmail_inject($mailfrom,$rcptto,$message);
	qmail_queue($envelope,$message);
}

# Local log and exit
sub bail {
	# 31: 554 mail server permanently rejected message (#5.3.0)
	# 111: 451 qq temporary problem (#4.3.0)
	my ($msg,$err) = @_;
	$err = 111 if !$err;
	warn $msg if $msg;
	$logsum{fate} = 'block';
	log_summary();
	exit $err;
}

# Check body against the config
sub check_body {
	my ($body) = @_;
	my $numl; $numl++ while ($body =~ m/\n/g);	# count lines
	my @bchks = $conf->val('body','body');
	warn "$logtag: Check body: $numl lines\n" if $verbose;
	$logsum{body} = $numl;
	foreach my $bchk (@bchks) {		# iterate over checks
		$bchk =~ s/^\~//;
		warn "$logtag: ...body =~ $bchk\n" if $verbose > 1;
		if ($body =~ m/$bchk/) {
			$checks_failed{body} = 1;
			if ($checks_dryrun{body}) {
				warn "$logtag: BLOCK DRYRUN body =~ $bchk (#4.3.0)\n";
			} else {
				bail("$logtag: BLOCK body =~ $bchk (#4.3.0)\n",111);
			}
		}
	}
}

# Check envelope sender (mail from) and recipients (rcppto) against config
sub check_envelope {
	my ($mailfrom,$rcptto) = @_;
	# mailfrom
	my @mf_checks = $conf->val('envelope','mailfrom');
	warn "$logtag: Check envelope: mailfrom $mailfrom\n" if $verbose;
	foreach my $mfchk (@mf_checks) {
		warn "$logtag: ...$mfchk\n" if $verbose > 1;
		if ($mfchk =~ s/^\~//) {
			if ($mailfrom =~ m/$mfchk/) {
				$checks_failed{envelope} = 1;
				if ($checks_dryrun{envelope}) {
					warn "$logtag: BLOCK DRYRUN envelope mailfrom $mailfrom =~ $mfchk (#4.3.0)\n";	
				} else {
					bail("$logtag: BLOCK envelope mailfrom $mailfrom =~ $mfchk (#4.3.0)\n",111);
				}
			}
		}
		else {
			if ($mailfrom eq $mfchk) {
				$checks_failed{envelope} = 1;
				if ($checks_dryrun{envelope}) {
					warn "$logtag: BLOCK DRYRUN envelope mailfrom $mailfrom == $mfchk (#4.3.0)\n";
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
	my ($email,$headers) = @_;
	
	# count headers for reporting
	my $numh;
	foreach my $h (@$headers) {
		my @hvals = $email->header($h);			# multiple instances of header (ex: received)
		$numh += scalar(@hvals);
	}
	warn "$logtag: Check headers: $numh headers\n" if $verbose;
	$logsum{headers} = $numh;
	
	# now iterate again (unfortunately) to run checks
	foreach my $h (@$headers) {					# headers from email
		my @hvals = $email->header($h);			# multiple instances of header (ex: received)
		my @hchks = $conf->val('headers',$h);	# multiple checks per header
		foreach my $hchk (@hchks) {				# iterate over checks
			if ($hchk =~ s/^\~//) {				# is regex check
				foreach my $hval (@hvals) {		# iterate over all of the header instances values
					warn "$logtag: ...$h: $hval =~ $hchk\n" if $verbose > 1;
					if ($hval =~ m/$hchk/) {	# match
						$checks_failed{headers} = 1;
						if ($checks_dryrun{headers}) {
							warn "$logtag: BLOCK DRYRUN header $h $hval =~ $hchk (#4.3.0)\n";
						} else {
							bail("$logtag: BLOCK header $h $hval =~ $hchk (#4.3.0)\n",111);
						}
					}
				}
			}
			else {
				foreach my $hval (@hvals) {		# iterate over all of the header instances values
					warn "$logtag: ...$h: $hval eq $hchk\n" if $verbose > 1;
					if ($hval eq $hchk) {
						$checks_failed{headers} = 1;
						if ($checks_dryrun{headers}) {
							warn "$logtag: BLOCK DRYRUN header $h $hval == $hchk (#4.3.0)\n";
						} else {
							bail("$logtag: BLOCK header $h $hval == $hchk (#4.3.0)\n",111);
						}
					}
				}
			}
		}
	}
}

# Ratelimit check analyzing envelope sender and number of recipients over interval
sub check_ratelimit {
	my ($mailfrom) = @_;
	if (!$mailfrom) { return; }
	warn "$logtag: Check ratelimit: mailfrom $mailfrom\n" if $verbose;
	
	my $maxrcptto = $conf->val('ratelimit','maxrcptto');
	my %skims = mine_qmail_skim_log("mailfrom=>$mailfrom");
	
	# figure out the beginning interval time after which we care about
	my $tbegin = time() - $conf->val('ratelimit','interval');
	my $tbegin_tai = unixtai64n($tbegin);
	print STDERR "$logtag: ...time_begin = $tbegin_tai (".tai64nlocal($tbegin_tai).") $tbegin\n" if ($verbose > 1);
	
	# iterate over logs grabbing only those within interval
	my $rcpttos;
	foreach my $tai (sort(keys(%skims))) {
		my $tunix = tai2unix($tai);
		if ($tunix > $tbegin) {
			print STDERR "$logtag: ...within_scope = $tai (".tai64nlocal($tai).") $tunix $skims{$tai}{mailfrom} $skims{$tai}{rcptto}\n" if ($verbose > 1);
			$rcpttos += $skims{$tai}{rcptto};
		}
	}
	
	$logsum{ratelimit} = $rcpttos;
	
	# determine fate
	if ($rcpttos > $conf->val('ratelimit','maxrcptto')) {
		$checks_failed{ratelimit} = 1;
		if ($checks_dryrun{ratelimit}) {
			warn "$logtag: BLOCK DRYRUN ratelimit mailfrom $mailfrom rcpttos $rcpttos greater than ".$conf->val('ratelimit','maxrcptto')." in interval ".$conf->val('ratelimit','interval')."s (#4.3.0)\n";
		} else {
			bail("$logtag: BLOCK ratelimit mailfrom $mailfrom rcpttos $rcpttos greater than ".$conf->val('ratelimit','maxrcptto')." in interval ".$conf->val('ratelimit','interval')."s (#4.3.0)\n",111);
		}
	}
}

# Phishhook check analyzing envelope sender, from header, number of envelope recipients
sub check_phishfrom {
	my ($mailfrom,$rcptto,$from) = @_;
	my $numrcpttos = scalar(split(/,/,$rcptto));
	my $from_sane = $from;	# Jeff Hardy <xhardy1@potsdam.edu>
	$from_sane =~ s/.*<//;
	$from_sane =~ s/>.*//;
	warn "$logtag: Check phishfrom: mailfrom $mailfrom from $from to $numrcpttos recipients\n" if $verbose;
	warn "$logtag: ...from_sane = $from_sane\n" if $verbose > 1;
	if (($mailfrom ne $from_sane) && ($numrcpttos > $conf->val('phishfrom','maxrcptto'))) {
		$checks_failed{phishfrom} = 1;
		if ($checks_dryrun{phishfrom}) {
			warn "$logtag: BLOCK DRYRUN phishfrom mailfrom $mailfrom != $from and greater than ".$conf->val('phishfrom','maxrcptto')." recipients (#4.3.0)\n";
		} else {
			bail("$logtag: BLOCK phishfrom mailfrom $mailfrom != $from and greater than ".$conf->val('phishfrom','maxrcptto')." recipients (#4.3.0)\n",111);
		}
	}
}

# Phishhook check analyzing country and time of last login
sub check_phishhook {
	my ($user) = @_;
	warn "$logtag: Check phishhook: authuser $user\n" if $verbose;
	if (!$user) { return; }
	
	# Discern the beginning of the interval
	my $tbegin = time() - $conf->val('phishhook','interval');
	my $tbegin_tai = unixtai64n($tbegin);
	print STDERR "$logtag: ...time_begin = $tbegin_tai (".tai64nlocal($tbegin_tai).") $tbegin\n" if ($verbose > 1);

	# Used below in checks to exclude current domestic logins and to 
	# exclude foreign to foreign hops as travellers
	my %safe_countries;
	foreach (split(',',$conf->val('phishhook','safe_countries'))) {
		$safe_countries{$_} = 1;
	}
	
	# Users who are excluded from phishhook check
	my %safe_users;
	foreach (split(',',$conf->val('phishhook','safe_users'))) {
		$safe_users{$_} = 1;
	}
	
	# Matt: Jeff: I was thinking maybe if we had a wtf user that it triggered 
	# on always, when that cca logged in, it just automatically snagged them.
	# Even better here in qmail-skim since we can set test params in the config.
	my ($test_user,@test_logins) = split(/,/,$conf->val('phishhook','test'));
	
	# Mine the logs or build fake ones out of phishhook test parameter
	my %skims;
	if ($test_user && $user eq $test_user) {
		warn "$logtag: ...parsing test phishhook parameters from config" if ($verbose > 1);
		foreach (@test_logins) {
			my ($tai,$country) = split(/s+/,$_);
			$skims{$tai}{authuser} = $user;
			$skims{$tai}{country} = $country;	
		}
	} else {
		%skims = mine_qmail_skim_log("authuser=>$user",$tbegin_tai);
	}
	my $geoip = Geo::IP->new(GEOIP_STANDARD);	
	
	my ($this_log,$last_log);
	
	# this login
	my ($this_tai,$this_ip) = split(/\s+/,$this_log);
	my $this_gentime = tai64nlocal($this_tai);
	my $this_unixtime = tai64nunix($this_tai);
	my $this_country = $geoip->country_code_by_addr($this_ip);
	
	$logsum{ipaddr} = $this_ip;
	$logsum{country} = $this_country;
	
	# last log
	my ($last_tai,$last_ip) = split(/\s+/,$last_log);
	my $last_gentime = tai64nlocal($last_tai);
	my $last_unixtime = tai64nunix($last_tai);
	my $last_country = $geoip->country_code_by_addr($last_ip);
	
	my $hours_diff = ($this_unixtime - $last_unixtime)/60/60;
	
	if ($verbose) {
		warn "$logtag: ...this_login = $this_tai ($this_gentime) $this_unixtime $this_ip $this_country\n" if ($verbose > 1);
		warn "$logtag: ...last_login = $last_tai ($last_gentime) $last_unixtime $last_ip $last_country\n" if ($verbose > 1);
		warn "$logtag: ...hours_diff = $hours_diff\n" if ($verbose > 1);
	}
	
	# phish logic
	
	# No idea where we are, so be safe
	if (!$this_country) {
		warn "$logtag: ...this country unknown, passed\n" if ($verbose > 1);
		return;
	}
	
	# Whitelisted user
	if (exists($safe_users{$user})) {
		warn "$logtag: ...user $user is whitelisted safe, passed\n" if ($verbose > 1);
		return;
	}
	
	# We don't have a prior login, so we're good
	if (!$last_country) {
		warn "$logtag: ...no prior login or last country unknown, passed\n" if ($verbose > 1);
		return;
	}
	
	# Haven't met a domestic (US, CA, etc) phisher yet
	if (exists($safe_countries{$this_country})) {
		warn "$logtag: ...this country $this_country is safe, passed\n" if ($verbose > 1);
		return;
	}
	
	# Didn't start here (US, CA, etc) probably on vacation
	if (!exists($safe_countries{$last_country})) {
		warn "$logtag: ...last country $last_country not safe maybe vacation, passed\n" if ($verbose > 1);
		return;
	}
	
	# No hop, we're good
	if ($last_country eq $this_country) {
		warn "$logtag: ...last country $last_country eq this_country $this_country, passed\n" if ($verbose > 1);
		return;
	}
	
	# Last login from VPN range, we assume good so travelers do not get snagged
	if ($last_ip =~ m/^137\.143\.78\.*/) {
		warn "$logtag: ...last_ip $last_ip within vpn range, passed\n" if ($verbose > 1);
		return; 	
	}
	
	# Math problem
	if ($hours_diff <= 0) {
		warn "$logtag: ...hours_diff $hours_diff <= 0 math oops and something wrong, passed\n" if ($verbose > 1);
		return;	
	}
	
	# Far enough time between hops, we're good
	my $hours_lapse = $conf->val('phishhook','hours_lapse');
	if ($hours_diff > $hours_lapse) {
		warn "$logtag: ...hours_diff $hours_diff > hours_lapse $hours_lapse, passed\n" if ($verbose > 1);
		return;
	}
	
	# If we get here: 
	#  - the user is not in the US,
	#  - the user has logged in in recent history,
	#  - the user is in a different country than they were last in,
	#  - the last login was not from the campus vpn range,
	#  - it has been less than the specified hours since the user was in the last country
	# 
	# We want to:
	#  - run a perl script that will
	#   + Create a ticket
	#   + FWBLACKLIST the current IP address
	#   + Scramble their password
	#   + Add them to the 'phish' group
	#  - block this session
	
	$checks_failed{phishhook} = 1;
	if ($checks_dryrun{phishhook}) {
		warn "$logtag: SNAG phishhook user $user: /opt/bin/phishhook_snag.pl $user $this_ip $last_gentime $last_ip $last_country\n";
		warn "$logtag: BLOCK DRYRUN phishook user $user for country-hopping from $last_ip ($last_country) to $this_ip ($this_country) in $hours_diff (#4.3.0)\n";
	} else {
		# snag the user
		my $exitval = system("/opt/bin/phishhook_snag.pl $user $this_ip $last_gentime $last_ip $last_country");
		$exitval >>= 8;
		warn "$logtag: SNAG phishhook user $user: /opt/bin/phishhook_snag.pl $user $this_ip $last_gentime $last_ip $last_country: $exitval\n";
		bail("$logtag: BLOCK phishook user $user for country-hopping from $last_ip ($last_country) to $this_ip ($this_country) in $hours_diff hours (#4.3.0)\n",111);
	}
}

# Debug to STDERR
sub debug {
	my ($email,$headers) = @_;
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
				warn "$logtag: DEBUG: \t$p=$_\n";
			}
		}
	}
	foreach my $h (@$headers) {
		my @vals = $email->header($h);	# assume all are multivalue
		foreach (@vals) {
			warn "$logtag: DEBUG: $h: $_\n";
		}
	}
	my $env = $envelope;
	$env =~ s/\0/\\0/g;	# convert nulls to printable string for debugging
	warn "$logtag: DEBUG: FD1: $env\n";
	warn "$logtag: DEBUG: FD0:\n$message\n" if $verbose > 3;
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

# Print the %logsum hash in a nice format to STDERR
# so that future mining can easily pull this info 
# back in as a hash.
sub log_summary {
	my $logline = "$logtag: SKIM ";
	$logsum{checksfailed} = join(',',sort(keys(%checks_failed))) if %checks_failed;
	foreach (sort(keys(%logsum))) {
		$logline .= $_.'=>'.$logsum{$_}.' ';
	}
	$logline =~ s/\s*$//g;	# trailing whitespace
	print STDERR "$logline\n";
}

# Parse qmail logs looking for all qmail-skim bits that match given string,
# ex: authuser=>$user, and are within bounds, ie at least as recent, as the 
# given TAI datestamp.
# Returns hash of hashes of all matching entries keyed by TAI datestamp.
sub mine_qmail_skim_log {
	my ($str,$tbegin_tai) = @_;
	return if (!$str || !$tbegin_tai);
	
	# Get list of logs whose TAI-stamped filename indicates they were updated 
	# more recently than our begin time.  Relying on the filename is less 
	# reliable than examining the tail of every log, since the stamp on the log
	# is fractions of a second later than the last entry typically, but this is 
	# much less intensive.  Of course, dumping this in the logs for later 
	# retrieval is not the most elegant solution to begin with.
	my @logs;
	opendir (LOGD,"$qmail_logs") or warn "$logtag: Cannot opendir $qmail_logs: $!\n";
	while (my $l = readdir(LOGD)) {
		if ($l =~ m/^@/) {      # @400000004f67d6612991d2a4.s
			my $lfile_tai = $l; $lfile_tai =~ s/\..*//;     # eliminate trailing .s
			if (($lfile_tai cmp $tbegin_tai) == 1) {        # lfile time greater (more recent) than tbegin therefore in bounds
				warn "$logtag: ......found log $l (".tai64nlocal($l).") in-bounds\n" if ($verbose > 2);
				push (@logs,$l);
			} else {
				warn "$logtag: ......found log $l (".tai64nlocal($l).") out-of-bounds\n" if ($verbose > 2);
			}
		}
	}
	closedir (LOGD);
	
	# Sorts naturally from oldest to most recent
	@logs = sort(@logs);
	
	# Cannot forget the current log since we will be there 99% of the time
	push (@logs,'current');

	# We have isolated all the log files in bounds by their timestamp
	# Now we iterate through them in order checking the time and 
	# string match of each individual skim entry
	my %skims;
	foreach my $l (@logs) {
		warn "$logtag: ...parsing log $qmail_logs/$l\n" if ($verbose > 1);
		open (LOG,"$qmail_logs/$l") or die "$logtag: Cannot open $qmail_logs/$l: $!\n";
		while (<LOG>) {
			# @400000004fa9e36514affb7c qmail-skim.pl[31859]: SKIM /
			# config=>/etc/qmail-skim-test.conf /
			# from=>qmailskim@potsdam.edu /
			# mailfrom=>qmailskim@potsdam.edu rcptto=>1
			if (m/qmail-skim.pl.*SKIM .*$str/) {
				m/(\S+) qmail-skim\.pl.* SKIM (.*)/;
				foreach (split(/\s+/,$2)) {
					my ($key,$val) = split(/=>/,$_);
					$skims{$1}{$key} = $val;
				}
				warn "$logtag: ......$1 (".tai64nlocal($1).") $2\n" if ($verbose > 2);
			}
		}
		close (LOG);
	}
	return %skims;
}

# Parse qmail logs looking for last qmail-smtpd smtp-auth login 
# by given username, returning ip address and timestamp.
# Returns list of this and last logins in form TAI timestamp and ip space-separated
sub mine_smtp_auth_log {
	my ($user) = @_;
	my @logins;
	# parse the current log
	if (-e "$qmail_logs/current") {
		warn "$logtag: ...parsing log $qmail_logs/current\n" if ($verbose > 1);
		open (LOG,"$qmail_logs/current") or warn "$logtag: Cannot open $qmail_logs/current: $!\n";
		while (<LOG>) {
			# @400000004f6769fb232759fc qmail-smtpd[713]: AUTH successful [137.143.102.113] xhardy1
			if (m/(\S+) qmail-smtpd.*AUTH successful \[(\S+)\] $user/) {
				push (@logins,"$1 $2");
				warn "$logtag: ......$1 (".tai64nlocal($1).") $2\n" if ($verbose > 2);
			}
		}
		close (LOG);
	}
	# parse the first historical log, as we may lack login info if it rolled
	if (scalar(@logins) < 2) {
		my @logs;
		opendir (LOGD,"$qmail_logs") or warn "$logtag: Cannot opendir $qmail_logs: $!\n";
		while (my $l = readdir(LOGD)) {
			if ($l =~ m/^@/) {	# @400000004f67d6612991d2a4.s
				warn "$logtag: ......found log $l (".tai64nlocal($l).")\n" if ($verbose > 2);
				push (@logs,$l);
			}
		}
		closedir (LOGD);
		@logs = sort(@logs);
		
		my $l = pop(@logs);	# just the last one
		warn "$logtag: ...parsing log $qmail_logs/$l\n" if ($verbose > 1);
		open (LOG,"$qmail_logs/$l") or die "$logtag: Cannot open $qmail_logs/$l: $!\n";
		while (<LOG>) {
			# @400000004f6769fb232759fc qmail-smtpd[713]: AUTH successful [137.143.102.113] xhardy1
			if (m/(\S+) qmail-smtpd.*AUTH successful \[(\S+)\] $user/) {
				push (@logins,"$1 $2");
				warn "$logtag: ......$1 (".tai64nlocal($1).") $2\n" if ($verbose > 2);
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
	
	warn "$logtag: Injecting message with $qmail_inject\n" if $verbose;
	
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

	warn "$logtag: Queueing message with $qmail_queue\n";
	
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
