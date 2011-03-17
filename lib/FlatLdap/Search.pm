package FlatLdap::Search;

# http://tools.ietf.org/html/rfc4511#section-4.5.1

use warnings;
use strict;
use feature "switch";
use Data::Dumper;

use FlatLdap::Schema;
use FlatLdap::Config;

use vars qw( $schema );

#  'filter' => {
#     'and' => [
#        {
#           'equalityMatch' => {
#               'assertionValue' => 'posixAccount',
#               'attributeDesc' => 'objectClass'
#           } 
#        },
#        {
#           'equalityMatch' => {
#               'assertionValue' => '5001',
#               'attributeDesc' => 'uidNumber'
#          } 
#        }
#     ] 
# },
# 
sub new
{
  my ($class, $filter) = @_;

  $schema = new FlatLdap::Schema();

  return bless { filter => $filter }, $class;  
}

#   for (values %users) {
#       if ( $search->match() ) {
#         push(@foundUsers, buildEntry($base, $_, 'posixAccount'));
#       }
#   }
#   return @foundUsers
sub match
{
  my $self = shift;
  my $obj = shift || $_;

  die "Invalid object in tree" unless $obj;

  return $self->evaluate($self->{filter}, $obj);
}

sub evaluate
{
  my ($self, $filter, $obj) = @_;

  my @cmd = keys %{$filter};
  my $subject = $filter->{$cmd[0]};

  given($cmd[0]) {
    when ('and')           { return $self->evalAnd($subject, $obj); };
    when ('or')            { return $self->evalOr($subject, $obj); };
    when ('not')           { return ! $self->evaluate($subject->[0], $obj) };
    when ('equalityMatch') { return $self->evalEqMatch($subject, $obj); };
    default { warn "Unknown command: $cmd[0]\n" }
  }
  
  return;
}

sub evalAnd
{
  my ($self, $subject, $obj) = @_;

  for (@{$subject}) {
    return 0 unless $self->evaluate($_, $obj);
  }

  return 1;
}

sub evalOr
{
  my ($self, $subject, $obj) = @_;

  for (@{$subject}) {
    return 1 if $self->evaluate($_, $obj);
  }

  return 0;
}

sub err
{
  my $config = new FlatLdap::Config();
  warn @_ if $config->{verbose};
  return 0; # no match
}

sub evalEqMatch
{
  my ($self, $subject, $obj) = @_;

  my $key = $subject->{attributeDesc};
  my $value = $subject->{assertionValue};

  # Assert $key is whitelisted
  return err( "Unknown key requested in attributeDesc: ", $key, "\n" )
    unless grep {
      m/^$key$/
    } @{$schema->{posixAccount}}, @{$schema->{posixGroup}}, 'objectClass';

  # Assert attributeDesc is set
  return err( "AttributeDesc not set\n")
    unless ($obj->{$key});

  if (ref($obj->{$key}) eq 'ARRAY') {
    for (@{$obj->{$key}}) {
      return 1 if $_ eq $value;
    }
  }
  else {
   return ( $obj->{$key} eq $value);
  }
}

1;
