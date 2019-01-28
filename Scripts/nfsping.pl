#!/usr/bin/perl
###############

##
#     tool:     nfsping.pl
#  version:     1.0
#   author:     H D Moore <hdmoore@digitaldefense.net>
#  purpose:     Quickly locate NFS servers on a network
#    usage:     Run with no arguments for usage options
#     bugs:     Nothing serious. Maybe checkmountd service on success.
#      url:     http://www.digitaloffense.net/index.html?section=TOOLS
##


use Socket;
use POSIX;
use Fcntl;

select(STDERR); $|++;
select(STDOUT); $|++;

my $net = shift() || die "usage: $0 <network/cidr>";
my $dport = 2049;

my @targets = ();
my $netblock = new nfspNetmask($net);
for $ip ($netblock->enumerate())
{
    push @targets, $ip;
}
shuffle(\@targets);

socket(S, PF_INET, SOCK_DGRAM, getprotobyname('udp'));
nonblock(S);

srand(time() + $$);


my $query =  "\x00\x00\x00\x00\x00\x00\x00" . 
             "\x02\x00\x01\x86\xa3\x00\x00" .
             "\x00\x00\x00\x00\x00\x00\x00" . 
             "\x00\x00\x00\x00\x00\x00\x00" .
             "\x00\x00\x00\x00\x00\x00\x00";

my $cnt = 0;
if($pid = fork())
{
    foreach $ip (@targets)
    {

        my $xid = chr(int(rand() * 255)) . chr(int(rand() * 255)) . 
                  chr(int(rand() * 255)) . chr(int(rand() * 255));
                  
        my $packet = $xid . $query;

        $dip = inet_aton($ip);
        $paddr = sockaddr_in($dport,$dip);
        send(S, $packet, 0, $paddr);
        usleep(0.0001);
        $cnt++;
        
        if(($cnt % 10) == 0)
        {
            print STDERR "              \r:: scanning $cnt/" . scalar(@targets) . "\r";
        }
    }
    print STDERR "              \r:: scanning $cnt/" . scalar(@targets);
    print STDERR "\n:: waiting for responses...\n";
    sleep(5);
    kill(9, $pid);
} else {
    my %responses = ();
    while(1)
    {
        if(($paddr = recv(S, $data, POSIX::BUFSIZ, 0)))
        {
            ($port, $addr) = sockaddr_in($paddr);
            $host = inet_ntoa($addr);
        
            if($data && $responses{$host} != 1)
            {
                print STDOUT "\nGot response from $host\n";
                $responses{$host} = 1;
            }
        }
    }
}   

close(S);

sub nonblock {
        my $socket = shift;
        my $flags;

        $flags=fcntl($socket,F_GETFL,0)
                || die "Can't get flags for socket: $!\n";
        fcntl($socket,F_SETFL,$flags|O_NONBLOCK)
                || die "Can't make socket nonblocking: $!\n";
}

sub shuffle {
    my $array = shift;
    my $i = scalar(@$array);
    my $j;
    foreach $item (@$array )
    {
        --$i;
        $j = int rand ($i+1);
        next if $i == $j;
        @$array [$i,$j] = @$array[$j,$i];
    }
    return @$array;
}

sub usleep {
    my ($nap) = @_;
    select(undef, undef, undef, $nap);
}

# ripped from Net::Netmask
package nfspNetmask;

use vars qw($VERSION);
$VERSION = 1.9;

require Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(findNetblock findOuterNetblock findAllNetblock
        cidrs2contiglists range2cidrlist);
@EXPORT_OK = qw(int2quad quad2int %quadmask2bits imask);

my $remembered = {};
my %quadmask2bits;
my %imask2bits;
my %size2bits;

use vars qw($error $debug);
$debug = 1;

use strict;
use Carp;

sub new
{
        my ($package, $net, $mask) = @_;

        $mask = '' unless defined $mask;

        my $base;
        my $bits;
        my $ibase;
        undef $error;

        if ($net =~ m,^(\d+\.\d+\.\d+\.\d+)/(\d+)$,) {
                ($base, $bits) = ($1, $2);
        } elsif ($net =~ m,^(\d+\.\d+\.\d+\.\d+):(\d+\.\d+\.\d+\.\d+)$,) {
                $base = $1;
                my $quadmask = $2;
                if (exists $quadmask2bits{$quadmask}) {
                        $bits = $quadmask2bits{$quadmask};
                } else {
                        $error = "illegal netmask: $quadmask";
                }
        } elsif (($net =~ m,^\d+\.\d+\.\d+\.\d+$,)
                && ($mask =~ m,\d+\.\d+\.\d+\.\d+$,))
        {
                $base = $net;
                if (exists $quadmask2bits{$mask}) {
                        $bits = $quadmask2bits{$mask};
                } else {
                        $error = "illegal netmask: $mask";
                }
        } elsif (($net =~ m,^\d+\.\d+\.\d+\.\d+$,) &&
                ($mask =~ m,0x[a-z0-9]+,i))
        {
                $base = $net;
                my $imask = hex($mask);
                if (exists $imask2bits{$imask}) {
                        $bits = $imask2bits{$imask};
                } else {
                        $error = "illegal netmask: $mask ($imask)";
                }
        } elsif ($net =~ /^\d+\.\d+\.\d+\.\d+$/ && ! $mask) {
                ($base, $bits) = ($net, 32);
        } elsif ($net =~ /^\d+\.\d+\.\d+$/ && ! $mask) {
                ($base, $bits) = ("$net.0", 24);
        } elsif ($net =~ /^\d+\.\d+$/ && ! $mask) {
                ($base, $bits) = ("$net.0.0", 16);
        } elsif ($net =~ /^\d+$/ && ! $mask) {
                ($base, $bits) = ("$net.0.0.0", 8);
        } elsif ($net =~ m,^(\d+\.\d+\.\d+)/(\d+)$,) {
                ($base, $bits) = ("$1.0", $2);
        } elsif ($net =~ m,^(\d+\.\d+)/(\d+)$,) {
                ($base, $bits) = ("$1.0.0", $2);
        } elsif ($net eq 'default') {
                ($base, $bits) = ("0.0.0.0", 0);
        } elsif ($net =~ m,^(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)$,) {
                # whois format
                $ibase = quad2int($1);
                my $end = quad2int($2);
                $error = "illegal dotted quad: $net"
                        unless defined($ibase) && defined($end);
                my $diff = ($end || 0) - ($ibase || 0) + 1;
                $bits = $size2bits{$diff};
                $error = "could not find exact fit for $net"
                        if ! defined($bits) && ! defined($error);
        } else {
                $error = "could not parse $net $mask";
        }

        carp $error if $error && $debug;

        $ibase = quad2int($base || 0) unless $ibase;
        $error = "could not parse $net $mask"
                unless defined($ibase) || defined($error);
        $ibase &= imask($bits)
                if defined $ibase && defined $bits;

        return bless {
                'IBASE' => $ibase,
                'BITS' => $bits,
                ( $error ? ( 'ERROR' => $error ) : () ),
        };
}

sub errstr { return $error; }
sub debug  { my $this = shift; return (@_ ? $debug = shift : $debug) }

sub base { my ($this) = @_; return int2quad($this->{'IBASE'}); }
sub bits { my ($this) = @_; return $this->{'BITS'}; }
sub size { my ($this) = @_; return 2**(32- $this->{'BITS'}); }
sub next { my ($this) = @_; int2quad($this->{'IBASE'} + $this->size()); }

sub imask
{
        return (2**32 -(2** (32- $_[0])));
}

sub enumerate
{
        my ($this, $bitstep) = @_;
        $bitstep = 32 unless $bitstep;
        my $size = $this->size();
        my $increment = 2**(32-$bitstep);
        my @ary;
        my $ibase = $this->{'IBASE'};
        for (my $i = 0; $i < $size; $i += $increment) {
                push(@ary, int2quad($ibase+$i));
        }
        return @ary;
}

sub quad2int
{
        my @bytes = split(/\./,$_[0]);

        return undef unless @bytes == 4 && ! grep {!(/\d+$/ && $_<256)} @bytes;

        return unpack("N",pack("C4",@bytes));
}

sub int2quad
{
        return join('.',unpack('C4', pack("N", $_[0])));
}

 
BEGIN {
        for (my $i = 0; $i <= 32; $i++) {
                $imask2bits{imask($i)} = $i;
                $quadmask2bits{int2quad(imask($i))} = $i;
                $size2bits{ 2**(32-$i) } = $i;
        }
}
1;
