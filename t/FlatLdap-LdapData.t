#!/usr/bin/perl -w

use Test::More tests => 9;

use FlatLdap::Data;
use FlatLdap::Config;

my $config = new FlatLdap::Config;

$config->{etc} = 't/etc';

my $ldapdata = new FlatLdap::Data();

ok(defined $ldapdata->{users},  'users are defined');
ok(!defined $ldapdata->{users}->{bestaatniet}, '  bestaatniet is !defined');
ok(defined $ldapdata->{users}->{bestaatwel}, '  bestaatwel is defined');
ok($ldapdata->{users}->{bestaatwel}->{uidNumber} == 5001, '  bestaatwel has uidNumber 5001');
ok($ldapdata->{users}->{bestaatwel}->{shadowMax} == 99999, '  bestaatwel has shadowMax 99999');

ok(defined $ldapdata->{groups}, 'groups are defined');
ok(defined $ldapdata->{groups}->{bestaatwel2gr}, '  bestaatwel2gr is defined');
ok($ldapdata->{groups}->{bestaatwel2gr}->{gidNumber} == 5003, '  bestaatwel2gr has gidNumber 5003');
is_deeply($ldapdata->{groups}->{bestaatwel2gr}->{objectClass}, [ "posixGroup"], '  bestaatwel2gr has objectClass posixGroup');

