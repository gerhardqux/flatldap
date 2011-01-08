package FlatLdap::Config;

use strict;
use warnings;

my $config = {
        verbose  => 0,
        debug    => 0,
        port     => 389,
        listen   => "0.0.0.0",
        chroot   => 1,
        cfgfile  => "/etc/flatldapd.conf",
        etc      => "/etc",
        fg       => 0,
        insecure => 0,
};

sub new {
	my $class = shift;
	$config ||= bless {}, $class;
	return $config;
}

1;
