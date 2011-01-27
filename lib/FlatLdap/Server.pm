package FlatLdap::Server;

use strict;
use warnings;
use feature "switch";
use Data::Dumper;
use FlatLdap::Data;
use FlatLdap::Config;
use FlatLdap::Schema;
use FlatLdap::Search;

use Net::LDAP::Constant qw(LDAP_SUCCESS LDAP_UNWILLING_TO_PERFORM);
use Net::LDAP::Server;
use base 'Net::LDAP::Server';
use fields qw();
use vars qw( $ldapdata $schema $config );

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

	$config = new FlatLdap::Config();

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

sub search
{
	my ($self, $reqData) = @_;

	warn "Searching...\n" if $config->{debug};
	warn Dumper($reqData) if $config->{debug};
	
	my $base = $config->{base};

	warn ("Wrong baseObject: '".$reqData->{baseObject}."', should be '$base'\n")
		unless $reqData->{baseObject} eq $base;
	
	my @entries;

	my $search = new FlatLdap::Search($reqData->{filter});
	for (values %{$ldapdata->{users}}) {
		if ( $search->match() ) {
			push(@entries, buildEntry($base, $_, 'posixAccount'));
		}
	}

	for (values %{$ldapdata->{groups}}) {
		if ( $search->match() ) {
			push(@entries, buildEntry($base, $_, 'posixGroup'));
		}
	}

	warn "Returning:\n" if $config->{debug};
	warn Dumper(\@entries) if $config->{debug};
	return RESULT_OK, @entries;
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

1;
