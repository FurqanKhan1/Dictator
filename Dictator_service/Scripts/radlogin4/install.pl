#!/usr/bin/perl

use File::Copy;
$cfg = &getcfg;

$ver = 500;
$dsnmax = 3;
$oldodbc = '/usr/local/iea/odbc.ini';
$initext = '';

if (-d '/etc/rc.d/init.d')
	{
	$initd = '/etc/rc.d/init.d';
	}
elsif (-d '/etc/init.d')
	{
	$initd = '/etc/init.d';
	}
else
	{
	$initd = '/usr/local/etc/rc.d';
	$initext = '.sh';
	}

if ($ver == 300)
	{
	$version = '3';
	}
elsif ($ver == 400)
	{
	$version = '4';
	}
elsif ($ver == 500)
	{
	$version = '5';
	}
else
	{
	$version = 'Unknown Version';
	}

$armed = 1;
$header = "Welcome to IEA Software, Inc.  UNIX Installer v$version ";

open(DATA,$cfg) || &fatal("Could not open $cfg for reading $!.  $cfg should be in the same directory as the installer");
@data = <DATA>;
close(DATA);

&include;			# Include install configuration files from sub directories.  They should know their not root
&syscheck;			# Check system and environment for known problems

@dirlist = grep(/^\//,@data);
@execlist = grep(/^\$/,@data);
@optionlist = grep(/^\d/,@data);
@filelist = grep(/^[a-z]/i,@data);

&exec(@execlist);		# Retreive global options
@hits = &optional(@optionlist);	# Welcome to installer and prompt for optional components
&makedirs(@dirlist);		# Check file directories

&install('base');		# Install Base files
&merant2freetds;

foreach(@hits)
	{
	&install($_);		# Install optional components
	}

&complete;			# Send success message.

sub exec
{
foreach(@_)
	{
	s/\n|\r//g;
	if (!defined eval($_))
		{
		exit;
		}
	}
}

sub install
{
my $group, $src, $dst, $required, description;
undef @runlist;
foreach(@filelist)
	{
	/^(\w+)/;
	if ($1 ne $_[0])
		{
		next;
		}
	s/\n|\r//g;
	($group,$src,$dst,$mode,$required,$description) = split(/\t+/);
	$src = &parseline($src);
	$dst = &parseline($dst);
	$mode = &parseline($mode);
	if ($group && $src && !$dst && !$mode && !$required && !$description)
		{
		push(@runlist,$src);
		}
	elsif (!-e $src && $required !~ /N/i && $src !~ /\*\.\w+$/)
		{
		&fatal("Required file $src ($description) missing from archive.  Reinstall this distribution.");
		}
	elsif (!-e $src && $src !~ /\*\.\w+$/)
		{
		&log("The file $src doesen't exist and is not required... skipping copy.");
		}
	else
		{
		if (-e $dst && $required !~ /O/i && $src !~ /\*\.\w+/)
			{
			&log("$dst already exists.  Skipping copy.");
			}
		else
			{
			if ($armed == 1)
				{
				if ($src =~ /(.*)\/\*\.(\w+)/)
					{
					$dir = $1;
					$extension = $2;
					opendir(DIRLIST,$dir) || &fatal("Can't open directory $dir for read $!");
					@dirlist = readdir(DIRLIST);
					closedir(DIRLIST);
					foreach(grep(/\.$extension$/,@dirlist))
						{
						if ($required !~ /O/i && -e "$dst/$_")
							{
							$msg = "$dst/$_ already exists.  Skipping copy.";
							}
						else
							{
							copy("$dir/$_",$dst) || &fatal("Copy $dir/$_ to $dst Failed $!");
							$msg = "Copy $dir/$_ -> $dst ($description) [OK]";
							}
						print "$msg\n";
						&log($msg);
						}
					}
				else
					{
					copy($src,$dst) || &fatal("Copy $src to $dst Failed $!");
					}
				chmod(oct($mode),$dst) || &log("Change mode for $dst failed.");
				}
			$msg = "Copy $src -> $dst ($description) [OK]";
			print "$msg\n";
			&log($msg);
			}
		}
	}

foreach(@runlist)
	{
	if ($armed == 1)
		{
		if (/srvinst\s*(\w+)/i)
			{
			$rc = &srvinst($1);
			}
		elsif (/nocheck\s*(.*)/i)
			{
			system($1);
			$rc = 0;
			}
		else
			{
			$rc = system($_);
			}
		}
	else
		{
		$rc = 0;
		}
	if ($rc)
		{
		&fatal("Exec $_ [Failed ($rc)]");
		}
	else
		{
		$msg = "Exec $_ [OK]";
		&log($msg);
		}
	}
}

sub makedirs
{
my $file,$mode;
foreach(@_)
	{
	s/\n|\r//g;
	($file,$mode) = split(/\t+/);
	$file = &parseline($file);
	$mode = &parseline($mode);
	if (!-d $file)
		{
		if ($armed == 1)
			{
			mkdir($file,oct($mode)) || &fatal("Can't create directory $file $!.");
			}
		&log("Directory $file created with mode $mode");
		}
	}
}

sub parseline
{
my $pl;
$pl = $_[0];
$pl =~ s/\$(\w+)/${$1}/g;
return $pl;
}

sub log
{
my $time;
if ($installog)
	{
	$time = localtime;
	open(LOG,">>$installog");
	if ($armed == 0)
		{
		print LOG "[Disarmed] $time $_[0]\n";
		}
	else
		{
		print LOG "$time $_[0]\n";
		}
	close(LOG);
	}
}

format = 
@<<< @<<<<<<<<<<<<<<<<<<   @<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
"$number.",$installed,$desc
.

sub optional
{
my %nmap, %dmap, %options, $number, $group, $desc, $installed, @retlist;

undef %nmap;
foreach(@_)
	{
	($number,$group,$desc) = split(/\t+/);
	$desc = &parseline($desc);
	$dmap{$group} = $desc;
	$nmap{$number} = $group;
	}
for(;;)
	{
	&cls;
	print qq#
$header

Select optional components to install from the list
by selecting the number of the option below.
Press 'C' to continue with the Installation or 'Q' to abort.

#;
	foreach(sort {$a <=> $b} @_)
		{
		s/\n|\r//g;
		($number,$group,$desc) = split(/\t+/);
		if ($options{$group} == 1)
			{
			$installed = '[Install]';
			}
		else
			{
			$installed = '[Do not Install]';
			}
		$desc = &parseline($desc);

		if (!$hidden{$group})
			{
			write;
			}
		}
	print "\n: ";
	$_ = <STDIN>;
	s/\r|\n//g;
	if ($_ =~ /^c$/i)
		{
		undef @retlist;
		foreach(keys(options))
			{
			if ($options{$_} == 1)
				{
				push(@retlist,$_);
				}
			}
		&cls;
		return @retlist;

		for(;;)
			{
			$_ = <STDIN>;
			$_ =~ s/\n|\r//g;
			if ($_ =~ /^c$/i)
				{
				return @retlist;
				}
			elsif ($_ =~ /^q$/i)
				{
				&abort;
				}
			elsif ($_ =~ /^r$/i)
				{
				last;
				}
			}
		}
	elsif ($_ =~ /^q$/i)
		{
		&abort;
		}
	elsif ($_ =~ /^(\d+)/)
		{
		$number = $1;
		$group = $nmap{$number};
		if ($group)
			{
			if ($options{$group} == 1)
				{
				$options{$group} = 0;
				}
			else
				{
				if ($group =~ /(\w+)(\d+)/)
					{
					foreach(keys(options))
						{
						if (/$1\d+/)
							{
							$options{$_} = 0;
							}						
						}
					}
				$options{$group} = 1;
				}
			}
		}
	}
}

sub cls
{
system('tput clear');
}

sub fatal
{
print "$_[0]\n";
&log($_[0]);
&abort;
}

sub abort
{
print "\nInstallation Aborted...\n";
if ($installog)
	{
	print "See $installog for details on any problems during this installation.\n";
	}
&log("Installation Aborted");
exit;
}

sub complete
{
print qq#
Installation completed successfully.
#;
&log("Installation Completed Successfully.");
}

sub getcfg
{
opendir(DIRLIST,'./') || &fatal("Can't open directory ./ for read $!");
@dirlist = readdir(DIRLIST);
closedir(DIRLIST);
@dirlist = grep(/install_[\w\_]+\.cfg/i,@dirlist);
foreach(@dirlist)
	{
	return $_;
	}
return 'install.cfg';
}

sub include
{
opendir(DIRLIST,'./') || die "Can't open current directory for read $!";
@dirlist = readdir(DIRLIST);
closedir(DIRLIST);

foreach $dir (@dirlist)
	{
	if ($dir !~ /\w/)
		{
		next;
		}

	if (-d $dir)
		{
		opendir(DIRLIST,$dir) || die "Can't open directory $dir for read $!";
		foreach $file (grep(/install_\w+\.cfg/,readdir(DIRLIST)))
			{
			open(DATA,"$dir/$file") || die "Can't open $dir/$file for read $!";
			while(<DATA>)
				{
				push(@data,$_);
				}
			close(DATA);
			}
		closedir(DIRLIST);
		}
	}
}

sub merant2freetds
{
my @mdata;
open(DATA,$oldodbc) || return;
@mdata = <DATA>;
close(DATA);

if (grep(/\/usr\/local\/iea\/E-/,@mdata))
	{
	foreach(@mdata)
		{
		s/Driver\s*=\s*\/usr\/local\/iea\/E-msss16\.so/Driver=\/usr\/local\/iea\/libtdsodbc\.so\nTDS_Version=7.0/i;
		s/Driver\s*=\s*\/usr\/local\/iea\/E-ase16\.so/Driver=\/usr\/local\/iea\/libtdsodbc\.so\nTDS_Version=5.0/i;
		s/NetworkAddress\s*=\s*([\w+\.]+)\s*\,\s*(\d+)/Server=$1\nPort=$2/i;
		s/Address\s*=\s*([\w+\.]+)\s*\,\s*(\d+)/Server=$1\nPort=$2/i;
		}

	open(DATA,">$oldodbc") || &fatal("Can't open $oldodbc for write $!");
	print DATA @mdata;
	close(DATA);
	}
}

sub srvinst
{
my $svc = $_[0];
if ($svc !~ /\w/)
	{
	&fatal("Invalid service parameter");
	}
if (-e '/sbin/chkconfig')
	{
	return system("chkconfig --add $svc");
	}
elsif (-e '/usr/sbin/update-rc.d')
	{
	return system("update-rc.d $svc defaults");
	}
else
	{
	return 0;
	}
}

sub syscheck
{
my $username = &whoami;
if ($armed == 1 && $username ne 'root')
	{
	&fatal("You must be logged on as root to perform this installation");
	}
}

sub whoami
{
(getpwuid($>))[0];
}
