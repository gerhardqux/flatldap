package LdapData;

use strict;
use warnings;
use Data::Dumper;

# constructor
sub new {
	my $class = shift;
	my $self = bless {
		users => {},
		groups => {},
	}, $class;
	$self->readFiles();
print Dumper($self);
	return $self;
}

sub readFiles
{
	my $self = shift;

	open(my $fh, '<', './passwd')
		or die($!);

	while(<$fh>) {
		chomp;
		my @row = split(':');
		$self->{users}{$row[0]} = {};
		my $obj = $self->{users}{$row[0]};

		$obj->{'uid'} = $row[0];
		$obj->{'userPassword'} = $row[1];
		$obj->{'uidNumber'} = $row[2];
		$obj->{'gidNumber'} = $row[3];
		$obj->{'gecos'} = $row[4];
		$obj->{'homeDirectory'} = $row[5];
		$obj->{'loginShell'} = $row[6];
		$obj->{'cn'} = $row[0];
		$obj->{'description'} = 'ddddeesssccc';
		$obj->{'objectClass'} = 'posixAccount';

	}
	close($fh);

	open(FH, './shadow')
		or die($!);

	while(<FH>) {
		chomp;
		my @row = split(':');
		my $uid = $row[0];
		#if (exists $self->{users}->[$uid]);
		my $obj = @{$self->{users}}{$uid};

		$obj->{'userPassword'} = $row[1];
		$obj->{'shadowLastChange'} = $row[2];
		$obj->{'shadowMax'} = $row[3];
		$obj->{'shadowMin'} = $row[4];
		$obj->{'shadowWarning'} = $row[5];
		$obj->{'shadowInactive'} = $row[6];
		$obj->{'shadowExpire'} = $row[7];
		$obj->{'shadowFlag'} = $row[8];
		$obj->{'objectClass'} = 'shadowAccount';
	}
	close FH;


	open($fh, '<', './group')
		or die($!);

	while(<$fh>) {
		chomp;
		my @row = split(':');
		my $gid = $row[0];
		$self->{groups}->{$gid} = {};
		my $obj = $self->{groups}->{$gid};

		$obj->{'cn'} = $row[0];
		$obj->{'userPassword'} = $row[1];
		$obj->{'gidNumber'} = $row[2];
		$obj->{'memberUid'} = $row[3];
		$obj->{'uniqueMember'} = '';
		$obj->{'objectClass'} = 'posixGroup';

	}
	close($fh);

	my @entries;
}

1;