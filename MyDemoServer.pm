package MyDemoServer;

use strict;
use warnings;
use Data::Dumper;
use LdapData;

use lib '../lib';
use Net::LDAP::Constant qw(LDAP_SUCCESS LDAP_UNWILLING_TO_PERFORM);
use Net::LDAP::Server;
use base 'Net::LDAP::Server';
use fields qw();
use vars qw( $ldapdata );

use constant RESULT_OK => {
	'matchedDN' => '',
	'errorMessage' => '',
	'resultCode' => LDAP_SUCCESS
};

# constructor
sub new {
	my ($class, $sock) = @_;
	my $self = $class->SUPER::new($sock);
	warn sprintf("Accepted connection from: %s\n", $sock->peerhost());
	$ldapdata = new LdapData();
	return $self;
}

# the bind operation
sub bind {
	my $self = shift;

	my $reqData = shift;
        unless ($reqData->{authentication}->{simple} eq '123root') {
		warn "Invalid credentials\n";
		warn Dumper($reqData);
		return {
	  		'matchedDN' => '',
          		'errorMessage' => 'Invalid credentials',
          		'resultCode' => LDAP_UNWILLING_TO_PERFORM
        	}
	}
	return RESULT_OK;
}

# the search operation
sub search {
	my $self = shift;
	my $reqData = shift;
	print "Searching...\n";
	print Dumper($reqData);
	my $base = $reqData->{'baseObject'};
	
	# plain die if dn contains 'dying'
	die("panic") if $base =~ /dying/;
	
	# return a correct LDAPresult, but an invalid entry
	return RESULT_OK, {test => 1} if $base =~ /invalid entry/;

	# return an invalid LDAPresult
	return {test => 1} if $base =~ /invalid result/;

	my @entries;
        my $attributeDesc;
	# onelevel or subtree
	if ($reqData->{'scope'}) {
		my $objectClass;
		my $uid;
warn 1;
		if ($reqData->{filter}->{'and'}) {
			$objectClass = $reqData->{filter}->{'and'}->[0]->{equalityMatch}->{assertionValue};
			if ( $reqData->{filter}->{'and'}->[1]->{'or'}) {
warn 2;
				$uid = $reqData->{filter}->{'and'}->[1]->{'or'}->[0]->{equalityMatch}->{assertionValue};
				$attributeDesc = $reqData->{filter}->{'and'}->{'or'}->[0]->{equalityMatch}->{attributeDesc};
			}
			else {
warn 3;
				$uid = $reqData->{filter}->{'and'}->[1]->{equalityMatch}->{assertionValue};
				$attributeDesc = $reqData->{filter}->{'and'}->[1]->{equalityMatch}->{attributeDesc};
			}
warn 4;
		}
		elsif ($reqData->{filter}->{equalityMatch}) {
warn 5;
				$uid = $reqData->{filter}->{'and'}->{'or'}->[1]->{equalityMatch}->{assertionValue};
			$objectClass = $reqData->{filter}->{equalityMatch}->{assertionValue};
		}
warn 6;
		warn "DEBUG: ObjectClass=$objectClass uid=$uid\n";

		if ($objectClass eq 'posixAccount') {
			if ($attributeDesc eq 'uidNumber') {
				push @entries, getPosixAccountByUid($base, $uid);
			}
			else {
				my @posixAccounts = getPosixAccounts($base, $uid);

				foreach my $posixAccount (@posixAccounts) {

					my $entry = Net::LDAP::Entry->new;
					$entry->dn($posixAccount->{dn});

					$entry->add( %{$posixAccount} );
					push @entries, $entry;
				}
			}
		}
		elsif ($objectClass eq 'shadowAccount') {
			my $dn = "cn=".$uid.", ou=Users, $base";
			my $shadowAccount = getShadowAccount($dn, $uid);
			if ($shadowAccount) {
				my $entry = Net::LDAP::Entry->new;
				$entry->dn($dn);

				$entry->add(%{$shadowAccount});
				push @entries, $entry;
			}
		}
		elsif ($objectClass eq 'posixGroup') {
			if ($attributeDesc eq 'cn') {
				push @entries, getPosixGroupsByCn($base, $uid);
			}
			elsif ($attributeDesc eq 'gidNumber') {
				push @entries, getPosixGroupsByGidNumber($base, $uid);
			}
			elsif ($attributeDesc eq 'memberUid') {
				push @entries, getPosixGroupsByMemberUid($base, $uid);
			}
			elsif ($attributeDesc eq 'uniqueMember') {
				push @entries, getPosixGroupsByUniqueMember($base, $uid);
			}
			elsif ($attributeDesc eq 'uid') {
				push @entries, getPosixGroupsByUid($base, $uid);
			}
			elsif ($attributeDesc eq 'uid') {
				# getPosixGroupsByUid
				my @posixGroups = getPosixGroups($uid);

				foreach my $posixGroup (@posixGroups) {
					my $entry = Net::LDAP::Entry->new;
					$entry->dn($posixGroup->{dn});

					$entry->add(%{$posixGroup});
					push @entries, $entry;
				}
			}
			else {
				push @entries, getAllPosixGroups($base);
			}
		}
	} else {
		# base
	}

	return RESULT_OK, @entries;
}

sub getPosixGroupsByUid
{
	exit 0;
	my $base = shift;
	my $um = shift;

	my %passwd;
	open(my $fh, '<', './passwd')
		or die($!);

	while(<$fh>) {
		chomp;
		my @row = split(':');
		$passwd{$row[0]} = [ @row ];
	}
	close($fh);

	my %group;
	open($fh, '<', './group')
		or die($!);

	while(<$fh>) {
		chomp;
		my @row = split(':');
		$group{$row[0]} = [ @row ];
	}
	close($fh);

	my @entries;

	
	return ();
}


# Test: id bestaatwel
sub getPosixGroupsByMemberUid
{
	my $base = shift;
	my $memberuid = shift;

	my %passwd;
	open(my $fh, '<', './passwd')
		or die($!);

	while(<$fh>) {
		chomp;
		my @row = split(':');
		$passwd{$row[0]} = [ @row ];
	}
	close($fh);

	my %group;
	open($fh, '<', './group')
		or die($!);

	while(<$fh>) {
		chomp;
		my @row = split(':');
		$group{$row[0]} = [ @row ];
	}
	close($fh);

	my @entries;

	if ($passwd{$memberuid}) {
		my $gid = $passwd{$memberuid}->[2];

		for my $group (values %group) {
			if ($group->[2] == $gid) {
				my $posixGroup = {
					'dn' => "cn=".$group->[0].", ou=Groups, $base",
					'cn' => $group->[0],
					'userPassword' => $group->[1],
					'gidNumber' => $group->[2],
					'memberUid' => $group->[3],
					'uniqueMember' => '',
					'objectClass' => 'posixGroup',
				};

				my $entry = Net::LDAP::Entry->new;
				$entry->dn($posixGroup->{dn});

				$entry->add(%{$posixGroup});
				push @entries, $entry;
			}
		}
	}
	
	for my $group (values %group) {
		my @members = split ',', $group->[3];
	 	for my $member (@members) {
			if ($member eq $memberuid) {
				my $posixGroup = {
					'dn' => "cn=".$group->[0].", ou=Groups, $base",
					'cn' => $group->[0],
					'userPassword' => $group->[1],
					'gidNumber' => $group->[2],
					'memberUid' => $group->[3],
					'uniqueMember' => '',
					'objectClass' => 'posixGroup',
				};

				my $entry = Net::LDAP::Entry->new;
				$entry->dn($posixGroup->{dn});

				$entry->add(%{$posixGroup});
				push @entries, $entry;
			}
		}
	}

	return @entries;
}


sub getPosixGroupsByUniqueMember
{
	exit 0;
	my $base = shift;
	my $um = shift;

	my %passwd;
	open(my $fh, '<', './passwd')
		or die($!);

	while(<$fh>) {
		chomp;
		my @row = split(':');
		$passwd{$row[0]} = [ @row ];
	}
	close($fh);

	my %group;
	open($fh, '<', './group')
		or die($!);

	while(<$fh>) {
		chomp;
		my @row = split(':');
		$group{$row[0]} = [ @row ];
	}
	close($fh);

	my @entries;

	
	return ();
}


sub getPosixGroupsByGidNumber
{
	my $base = shift;
	my $gid = shift;

	my %group;
	open(my $fh, '<', './group')
		or die($!);

	while(<$fh>) {
		chomp;
		my @row = split(':');
		$group{$row[0]} = [ @row ];
	}
	close($fh);

	my @entries;

	foreach my $group (values %group) {
		next unless $group->[2] == $gid;

		my $posixGroup = {
			'dn' => "cn=".$group->[0].", ou=Groups, $base",
			'cn' => $group->[0],
			'userPassword' => $group->[1],
			'gidNumber' => $group->[2],
			'memberUid' => $group->[3],
			'uniqueMember' => '',
			'objectClass' => 'posixGroup',
		};

		my $entry = Net::LDAP::Entry->new;
		$entry->dn($posixGroup->{dn});

		$entry->add(%{$posixGroup});
		push @entries, $entry;

		return @entries;
	}
	return ();
}

sub getPosixGroupsByCn
{
	my $base = shift;
	my $cn = shift;

	my %group;
	open(my $fh, '<', './group')
		or die($!);

	while(<$fh>) {
		chomp;
		my @row = split(':');
		$group{$row[0]} = [ @row ];
	}
	close($fh);

	my @entries;

	if ($cn) {
		if (exists $group{$cn}) {

			my $posixGroup = {
				'dn' => "cn=".$cn.", ou=Groups, $base",
				'cn' => $cn,
				'userPassword' => $group{$cn}->[1],
				'gidNumber' => $group{$cn}->[2],
				'memberUid' => $group{$cn}->[3],
				'uniqueMember' => '',
				'objectClass' => 'posixGroup',
			};

			my $entry = Net::LDAP::Entry->new;
			$entry->dn($posixGroup->{dn});

			$entry->add(%{$posixGroup});
			push @entries, $entry;

			return @entries;
		}
	}
	return ();
}

sub getAllPosixGroups
{
	my $base = shift;

	my %group;
	open(my $fh, '<', './group')
		or die($!);

	while(<$fh>) {
		chomp;
		my @row = split(':');
		$group{$row[0]} = [ @row ];
	}
	close($fh);

	my @entries;

	foreach my $cn (keys %group) {

		my $posixGroup = {
			'dn' => "cn=".$cn.", ou=Groups, $base",
			'cn' => $cn,
			'userPassword' => $group{$cn}->[1],
			'gidNumber' => $group{$cn}->[2],
			'memberUid' => $group{$cn}->[3],
			'uniqueMember' => '',
			'objectClass' => 'posixGroup',
		};

		my $entry = Net::LDAP::Entry->new;
		$entry->dn($posixGroup->{dn});

		$entry->add(%{$posixGroup});
		push @entries, $entry;
	}
	return @entries;
}

sub getPosixGroups
{
	my $base = shift;
	my $uid = shift;

	return unless $uid;

	die("...");

	if (exists $ldapdata->{users}->{$uid}) {
		warn Dumper($ldapdata->{users}->{$uid});

	}
	return;

	return getPosixAccounts($base, $uid);
}

sub getPosixAccountByUid
{
	my $base = shift;
	my $uid = shift;

	my %passwd;
	open(my $fh, '<', './passwd')
		or die($!);

	while(<$fh>) {
		chomp;
		my @row = split(':');
		$passwd{$row[0]} = [ @row ];
	}
	close($fh);

	my @entries;

	for my $passwd (values %passwd) {
		next unless $passwd->[2] == $uid;

		my $posixAccount = {
			'dn' => "cn=".$passwd->[0].", ou=Users, $base",
			'uid' => $passwd->[0],
			'userPassword' => $passwd->[1],
			'uidNumber' => $passwd->[2],
			'gidNumber' => $passwd->[3],
			'cn' => $passwd->[0],
			'homeDirectory' =>$passwd->[5],
			'loginShell' => $passwd->[6],
			'gecos' => $passwd->[4],
			'description' => 'ddddeesssccc',
			'objectClass' => 'posixAccount',
		};

		my $entry = Net::LDAP::Entry->new;
		$entry->dn($posixAccount->{dn});

		$entry->add(%{$posixAccount});
		push @entries, $entry;

		return @entries;
	}
	return ();
}


sub getPosixAccounts
{
	my $base = shift;
	my $uid = shift;

	if ($uid) {
		my $obj = $ldapdata->{users}->{$uid}
			or return ();

		my $dn = "cn=".$uid.", ou=Users, $base";
	
		return ( {
			'dn' => $dn,
			'uid' => $uid,
			'userPassword' => $obj->{userPassword},
			'uidNumber' => $obj->{uidNumber},
			'gidNumber' => $obj->{gidNumber},
			'cn' => 'TestCn',
			'homeDirectory' => $obj->{homeDirectory},
			'loginShell' => $obj->{loginShell},
			'gecos' => $obj->{gecos},
			'description' => 'ddddeesssccc',
			'objectClass' => 'posixAccount',
		} );
	}
	else {
		my @entries = ();
		foreach my $obj (values %{$ldapdata->{users}} ) {
			my $dn = "cn=".$obj->{uid}.", ou=Users, $base";
			push(@entries, {
				'dn' => $dn,
				'uid' => $obj->{uid},
				'userPassword' => $obj->{userPassword},
				'uidNumber' => $obj->{uidNumber},
				'gidNumber' => $obj->{gidNumber},
				'cn' => 'testCn',
				'homeDirectory' => $obj->{homeDirectory},
				'loginShell' => $obj->{loginShell},
				'gecos' => $obj->{gecos},
				'description' => 'ddddeesssccc',
				'objectClass' => 'posixAccount',
				} );
		}
		return @entries;
	}
	return [];
}

sub getShadowAccount
{
	my $dn = shift;
	my $uid = shift;

	my %shadow;
	open(FH, './shadow')
		or die($!);

		while(<FH>) {
			chomp;
			my @row = split(':');
			$shadow{$row[0]} = [ @row ];
		}
	close FH;

	if (exists $shadow{$uid}) {
		return {
			'dn' => $dn,
			'uid' => $shadow{$uid}->[0],
			'userPassword' => $shadow{$uid}->[1],
			'shadowLastChange' =>$shadow{$uid}->[2],
			'shadowMax' =>$shadow{$uid}->[3],
			'shadowMin' =>$shadow{$uid}->[4],
			'shadowWarning' =>$shadow{$uid}->[5],
			'shadowInactive' =>$shadow{$uid}->[6],
			'shadowExpire' => $shadow{$uid}->[7],
			'shadowFlag' => $shadow{$uid}->[8],
			'objectClass' => 'shadowAccount',
		}
	}

	return {};
}
		
1;
