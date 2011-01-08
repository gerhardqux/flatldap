package Fake::RunningInetSocket;

use strict;
use warnings;

sub new
{
	my $class = shift;
	return bless {}, $class;
}

sub peerhost
{
	return "0.0.0.0";
}

1;
