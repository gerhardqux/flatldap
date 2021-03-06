package FlatLdap::Data;

use strict;
use warnings;
use Data::Dumper;
use FlatLdap::Config;

my $singleton;

# constructor
sub new {
	my $class = shift;
	$singleton ||= bless {}, $class;
	$singleton->readFiles() unless exists $singleton->{users};
	return $singleton;
}

sub readFiles
{
	my $self = shift;
	my $config = new FlatLdap::Config();
	
	$self->{users} = {};
	$self->{groups} = {};

	open(my $fh, '<', $config->{etc}.'/passwd')
		or die($!);

	while(<$fh>) {
		chomp;
		my @row = split(':');
		next if $row[2] <= 1000;
		$self->{users}{$row[0]} = {};
		my $obj = $self->{users}{$row[0]};

		$obj->{uid} = $row[0];
		$obj->{userPasswordIntern} = $row[1];
		$obj->{userPassword} = '*';
		$obj->{uidNumber} = $row[2];
		$obj->{gidNumber} = $row[3];
		$obj->{gecos} = $row[4];
		$obj->{homeDirectory} = $row[5];
		$obj->{loginShell} = $row[6];
		$obj->{cn} = $row[0];
		$obj->{description} = 'ddddeesssccc';
		$obj->{objectClass} = ['posixAccount'];

	}
	close($fh);

	open($fh, $config->{etc}.'/shadow')
		or die($!);

	while(<$fh>) {
		chomp;
		my @row = split(':');
		my $uid = $row[0];

		die "Shadow user $uid not found in passwd\n" unless exists $self->{users}->{$uid};

		my $obj = @{$self->{users}}{$uid};

		$obj->{userPasswordIntern} = $row[1];
		$obj->{userPassword} = '*';
		$obj->{shadowLastChange} = $row[2];
		$obj->{shadowMax} = $row[3];
		$obj->{shadowMin} = $row[4];
		$obj->{shadowWarning} = $row[5];
		$obj->{shadowInactive} = $row[6];
		$obj->{shadowExpire} = $row[7];
		$obj->{shadowFlag} = $row[8];
		push(@{$obj->{objectClass}}, 'shadowAccount');
	}
	close $fh;


	open($fh, '<', $config->{etc}.'/group')
		or die($!);

	while(<$fh>) {
		chomp;
		my @row = split(':');
		next if $row[2] <= 1000;
		my $gid = $row[0];
		$self->{groups}->{$gid} = {};
		my $obj = $self->{groups}->{$gid};

		$row[3] ||= '';
		$obj->{cn} = $row[0];
		$obj->{userPassword} = $row[1];
		$obj->{gidNumber} = $row[2];
		$obj->{memberUid} = [split(/,/, $row[3]) ] ;
		$obj->{uniqueMember} = '';
		$obj->{objectClass} = ['posixGroup'];
	}
	close($fh);


	for my $user (values %{$self->{users}} ) {
		for my $group (values %{$self->{groups}} ) {
			next if $group->{gidNumber} ne $user->{gidNumber};
			push @{$group->{memberUid}}, $user->{cn};
		}
	}

	for my $group (values %{$self->{groups}} ) {
		$group->{uniqueMember} = [];

		for (@{$group->{memberUid}}) {
			push @{$group->{uniqueMember}}, "$_, ou=Users, ".$config->{base};
		}
	}
}

1;
