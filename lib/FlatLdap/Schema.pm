package FlatLdap::Schema;

use warnings;
use strict;

my $singleton;

sub new
{
	my $class = shift;

	$singleton ||= bless {}, $class;
        $singleton->init() unless exists $singleton->{posixAccount};
        return $singleton;
}

sub init
{
	my $self = shift;

	$self->{posixAccount} = [ qw(
		uid userPassword uidNumber gidNumber gecos homeDirectory
                loginShell cn description
        ) ];

	$self->{shadowAccount} = [ qw(
		userPassword shadowLastChange shadowMax shadowMin shadowWarning
		shadowInactive shadowExpire shadowFlag
	) ];

	$self->{posixGroup} = [ qw(
		cn userPassword gidNumber memberUid uniqueMember
	) ];
}

1;

