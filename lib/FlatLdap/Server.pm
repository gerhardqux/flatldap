package FlatLdap::Server;

use strict;
use warnings;
use feature "switch";
use Data::Dumper;
use FlatLdap::Data;
use FlatLdap::Config;
use FlatLdap::Schema;

use Net::LDAP::Constant qw(LDAP_SUCCESS LDAP_UNWILLING_TO_PERFORM);
use Net::LDAP::Server;
use base 'Net::LDAP::Server';
use fields qw();
use vars qw( $ldapdata $schema );

use constant RESULT_INVALID => {
	'matchedDN' => '',
	'errorMessage' => 'Invalid request',
	'resultCode' => LDAP_UNWILLING_TO_PERFORM,
};

use constant RESULT_OK => {
	'matchedDN' => '',
	'errorMessage' => '',
	'resultCode' => LDAP_SUCCESS,
};

# constructor
sub new {
	my ($class, $sock) = @_;
	my $self = $class->SUPER::new($sock);
	my $config = new FlatLdap::Config();
	warn sprintf("Accepted connection from: %s\n", $sock->peerhost()) if $config->{verbose};

	$ldapdata = new FlatLdap::Data();
	$schema = new FlatLdap::Schema();

	return $self;
}

sub err {
	warn $_[0]."\n";
	return {
		'matchedDN' => '',
		'errorMessage' => 'Invalid request',
		'resultCode' => LDAP_UNWILLING_TO_PERFORM,
	}
}

# the bind operation
#
# TODO only return shadow information when machine privileges are used
sub bind {
	my $self = shift;
	my $reqData = shift;
	my $config = new FlatLdap::Config();

        unless ($config->{insecure} || $reqData->{authentication}->{simple} eq '123root') {
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

	my $config = new FlatLdap::Config();

	warn "Searching...\n" if $config->{debug};
	warn Dumper($reqData) if $config->{debug};

	# TODO: cmp baseObject against config
	my $base = $config->{base};
	
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

		if ($reqData->{filter}->{'and'}) {
			$objectClass = $reqData->{filter}->{'and'}->[0]->{equalityMatch}->{assertionValue};
			if ( $reqData->{filter}->{'and'}->[1]->{'or'}) {

				$uid = $reqData->{filter}->{'and'}->[1]->{'or'}->[0]->{equalityMatch}->{assertionValue};
				$attributeDesc = $reqData->{filter}->{'and'}->{'or'}->[0]->{equalityMatch}->{attributeDesc};
			}
			else {

				$uid = $reqData->{filter}->{'and'}->[1]->{equalityMatch}->{assertionValue};
				$attributeDesc = $reqData->{filter}->{'and'}->[1]->{equalityMatch}->{attributeDesc};
			}

		}
		elsif ($reqData->{filter}->{equalityMatch}) {
			#	$uid = $reqData->{filter}->{'and'}->{'or'}->[1]->{equalityMatch}->{assertionValue};
			$objectClass = $reqData->{filter}->{equalityMatch}->{assertionValue};
		}

		return err("Illegal uid: $uid") if defined $uid && $uid !~ m/^[a-z0-9]+$/i;
		return err("Illegal objectClass: $objectClass") if defined $objectClass && $objectClass !~ m/^[a-z0-9]+$/i;
		return err("Illegal attributeDesc: $attributeDesc") if defined $attributeDesc && $attributeDesc !~ m/^[a-z0-9]+$/i;

		#warn "DEBUG: ObjectClass=$objectClass uid=$uid attr=$attributeDesc\n";

		if ($objectClass eq 'posixAccount') {
			if (defined $attributeDesc && $attributeDesc eq 'uidNumber') {
				push @entries, getPosixAccountByUidNumber($base, $uid);
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
			given ($attributeDesc) { 
				when ('cn')           { push @entries, getPosixGroupsByCn($base, $uid); }
				when ('gidNumber')    { push @entries, getPosixGroupsByGidNumber($base, $uid); }
				when ('memberUid')    { push @entries, getPosixGroupsByMemberUid($base, $uid); }
				when ('uniqueMember') { push @entries, getPosixGroupsByUniqueMember($base, $uid); }
				when ('uid')          { push @entries, getPosixGroupsByUid($base, $uid); }
				when ('uid') {
					# getPosixGroupsByUid
					my @posixGroups = getPosixGroups($uid);

					foreach my $posixGroup (@posixGroups) {
						my $entry = Net::LDAP::Entry->new;
						$entry->dn($posixGroup->{dn});

						$entry->add(%{$posixGroup});
						push @entries, $entry;
					}
				}
				default { push @entries, getAllPosixGroups($base); }
			}
		}
	} else {
		# base
	}

	warn "Returning:\n" if $config->{debug};
	warn Dumper(\@entries) if $config->{debug};
	return RESULT_OK, @entries;
}

sub getPosixGroupsByUid
{
	die("...");
	my $base = shift;
	my $um = shift;

	return;
}


# Test: id bestaatwel
sub getPosixGroupsByMemberUid
{
	my $base = shift;
	my $memberuid = shift;

	my @entries;

	my $user = $ldapdata->{users}->{$memberuid};

	if ($user) {
		my $gidn = $user->{gidNumber};

		for my $obj (values %{$ldapdata->{groups}}) {
			if ($obj->{gid} == $gidn) {
				push @entries, buildEntry($base, $obj);
			}
		}
	}
	
	for my $obj (values %{$ldapdata->{groups}}) {
		# 
		# TODO my @members = split ',', $group->members;
		my @members = ();
	 	for my $member (@members) {
			if ($member eq $memberuid) {
				push @entries, buildEntry($base, $obj);
			}
		}
	}

	return @entries;
}


sub getPosixGroupsByUniqueMember
{
	die("...");

	my $base = shift;
	my $um = shift;
}

sub buildEntry
{
	my ($base, $obj, $objectClass) = @_;
	 
	my $ou = 'Uncategorized';

	$ou = 'Groups' if $objectClass eq 'posixGroup';
	$ou = 'Users'  if $objectClass eq 'posixAccount';
	$ou = 'Users'  if $objectClass eq 'shadowAccount';

	my %entryHash = map {
		$_ => $obj->{$_}
	} @{$schema->{$objectClass}};

	$entryHash{dn} = "cn=".$obj->{cn}.", ou=$ou, $base";
	$entryHash{objectClass} = $objectClass;

	my $entry = Net::LDAP::Entry->new;
	$entry->dn($entryHash{dn});

	$entry->add(%entryHash);
	return $entry;
}

sub getPosixGroupsByGidNumber
{
	my $base = shift;
	my $gidNumber = shift;

	my @entries;

	foreach my $obj (values %{$ldapdata->{groups}}) {
		next unless $obj->{gidNumber} == $gidNumber;

		push(@entries, buildEntry($base, $obj, 'posixGroup'));

		return @entries;
	}
	return;
}

sub getPosixGroupsByCn
{
	my $base = shift;
	my $cn = shift;

	my @entries;

	if ($cn) {
		my $obj = $ldapdata->{groups}->{cn}
			or return;

		push @entries, buildEntry($base, $obj, 'posixGroup');

		return @entries;
	}

	return;
}

sub getAllPosixGroups
{
	my $base = shift;

	my @entries;

	foreach my $obj (values %{$ldapdata->{groups}}) {
		push @entries, buildEntry($base, $obj, 'posixGroup');
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

sub getPosixAccountByUidNumber
{
	my $base = shift;
	my $uidNumber = shift;

	my @entries;

	for my $obj (values %{$ldapdata->{users}}) {
		next unless $obj->{uidNumber} == $uidNumber;

		push @entries, buildEntry($base, $obj, 'posixAccount');

		return @entries;
	}
	return;
}


sub getPosixAccounts
{
	my $base = shift;
	my $uid = shift;

	if ($uid) {
		my $obj = $ldapdata->{users}->{$uid}
			or return;

		my $dn = "cn=".$uid.", ou=Users, $base";
	
		return ( {
			'dn'            => $dn,
			'uid'           => $uid,
			'userPassword'  => $obj->{userPassword},
			'uidNumber'     => $obj->{uidNumber},
			'gidNumber'     => $obj->{gidNumber},
			'cn'            => 'TestCn',
			'homeDirectory' => $obj->{homeDirectory},
			'loginShell'    => $obj->{loginShell},
			'gecos'         => $obj->{gecos},
			'description'   => 'ddddeesssccc',
			'objectClass'   => 'posixAccount',
		} );
	}
	else {
		my @entries = ();
		foreach my $obj (values %{$ldapdata->{users}} ) {
			my $dn = "cn=".$obj->{uid}.", ou=Users, $base";
			push(@entries, {
				'dn'             => $dn,
				'uid'            => $obj->{uid},
				'userPassword'   => $obj->{userPassword},
				'uidNumber'      => $obj->{uidNumber},
				'gidNumber'      => $obj->{gidNumber},
				'cn'             => 'testCn',
				'homeDirectory'  => $obj->{homeDirectory},
				'loginShell'     => $obj->{loginShell},
				'gecos'          => $obj->{gecos},
				'description'    => 'ddddeesssccc',
				'objectClass'    => 'posixAccount',
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

	my $obj = $ldapdata->{users}->{$uid}
		or return {};

	return { 
		'dn'               => $dn,
		'uid'              => $uid,
		'userPassword'     => $obj->{userPassword},
		'shadowLastChange' => $obj->{shadowLastChange},
		'shadowMax'        => $obj->{shadowMax},
		'shadowMin'        => $obj->{shadowMin},
		'shadowWarning'    => $obj->{shadowWarning},
		'shadowInactive'   => $obj->{shadowInactive},
		'shadowExpire'     => $obj->{shadowExpire},
		'shadowFlag'       => $obj->{shadowFlag},
		'objectClass'      => 'shadowAccount',
	};
}
		
1;
