#!/usr/bin/perl -w

use warnings;
use strict;

use Test::Simple tests => 17;

use Net::LDAP::Constant qw(LDAP_SUCCESS LDAP_UNWILLING_TO_PERFORM);
use lib 't/lib';
use Fake::RunningInetSocket;
use FlatLdap::Server;
use FlatLdap::Config;

my $config = new FlatLdap::Config;

$config->{etc} = 't/etc';

my $sock = new Fake::RunningInetSocket;

my $server = new FlatLdap::Server($sock);

my $result = $server->bind( { authentication => { simple => '123root' } } );
ok($result->{resultCode} == LDAP_SUCCESS, "bind succeeded");

my @result = $server->search( {
          'timeLimit' => 0,
          'baseObject' => 'dc=qrux,dc=nl',
          'filter' => {
                        'equalityMatch' => {
                                             'assertionValue' => 'posixAccount',
                                             'attributeDesc' => 'objectClass'
                                           }
                      },
          'sizeLimit' => 0,
          'typesOnly' => 0,
          'derefAliases' => 0,
          'attributes' => [
                            'uid',
                            'userPassword',
                            'uidNumber',
                            'gidNumber',
                            'cn',
                            'homeDirectory',
                            'loginShell',
                            'gecos',
                            'description',
                            'objectClass'
                          ],
          'scope' => 2
        });

ok(defined $result[1], "result[1] exists");
ok(exists $result[1]->{attrs}, "result[1]->{attrs} exists");
ok(exists $result[1]->{attrs}->{uid}, "result[1]->{attrs}->{uid} exists");

ok($result[1]->{attrs}->{uid}->[0] eq 'bestaatwel', "user 'bestaatwel' found");
ok($result[1]->{attrs}->{uidnumber}->[0] eq '5001', "  user 'bestaatwel' has uidNumber 5001");
ok($result[1]->{asn}->{objectName} eq 'cn=bestaatwel, ou=Users, dc=qrux, dc=nl',
 "  objectName 'bestaatwel' correct");

ok($result[2]->{attrs}->{uid}->[0] eq 'bestaatwel2', "user 'bestaatwel2' found");
ok($result[2]->{attrs}->{uidnumber}->[0] == 5002, "  user 'bestaatwel2' has uidNumber 5002");
ok($result[2]->{asn}->{objectName} eq 'cn=bestaatwel2, ou=Users, dc=qrux, dc=nl',
 "  objectName 'bestaatwel2' correct");

@result = $server->search( {
          'timeLimit' => 0,
          'baseObject' => 'dc=qrux,dc=nl',
          'filter' => {
                        'and' => [
                                   {
                                     'equalityMatch' => {
                                                          'assertionValue' => 'posixAccount',
                                                          'attributeDesc' => 'objectClass'
                                                        } 
                                   },
                                   {
                                     'equalityMatch' => {
                                                          'assertionValue' => '5001',
                                                          'attributeDesc' => 'uidNumber'
                                                        } 
                                   }
                                 ] 
                      },
          'sizeLimit' => 1,
          'sizeLimit' => 1,
          'typesOnly' => 0,
          'derefAliases' => 0,
          'attributes' => [
                            'uid',
                            'userPassword',
                            'uidNumber',
                            'gidNumber',
                            'cn',  
                            'homeDirectory',
                            'loginShell',
                            'gecos',
                            'description',
                            'objectClass'
                          ],
          'scope' => 2
});

ok(defined $result[1], "result[1] exists");
ok(exists $result[1]->{attrs}, "result[1]->{attrs} exists");
ok(exists $result[1]->{attrs}->{cn}, "result[1]->{attrs}->{cn} exists");

ok($result[1]->{attrs}->{uid}->[0] eq 'bestaatwel', "user 'bestaatwel' found");
ok($result[1]->{attrs}->{uidnumber}->[0] eq '5001', "  user 'bestaatwel' has uidNumber 5001");
ok($result[1]->{asn}->{objectName} eq 'cn=bestaatwel, ou=Users, dc=qrux, dc=nl',
 "  objectName 'bestaatwel' correct");

ok(!defined $result[2], "result[2] !exists");
