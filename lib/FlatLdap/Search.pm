package FlatLdap::Search;

# http://tools.ietf.org/html/rfc4511#section-4.5.1

use warnings;
use strict;
use feature "switch";
use Data::Dumper;

use FlatLdap::Schema;

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
    when ('and') {
      for (@{$subject}) {
        return 0 unless $self->evaluate($_, $obj);
      }
      return 1;
    }

    when ('or') {
      for (@{$subject}) {
        return 1 if $self->evaluate($_, $obj);
      }
      return 0;
    }

    when ('not') {
      return ! $self->evaluate($subject->[0], $obj);
    }

    when ('equalityMatch') {

      # Sanity-check, to see if someone is fooling with us
      # Only compare valid object-fields (from posixAccounts and posixGroups)
      my @arr = grep {
        m/$subject->{attributeDesc}/
      } @{$schema->{posixAccount}}, @{$schema->{posixGroup}}, 'objectClass';
      unless (@arr) {
        warn "Unknown key requested in attributeDesc: ".$subject->{attributeDesc}."\n";
        return 0;
      }

      # Sanity check, assert attributeDesc is set
      unless ($obj->{$subject->{attributeDesc}}) {
        warn "AttributeDesc not set\n";
        return 0;
      }

      if (ref($obj->{$subject->{attributeDesc}}) eq 'ARRAY') {
        for (@{$obj->{$subject->{attributeDesc}}}) {
          return 1 if $_ eq $subject->{assertionValue};
        }
      }
      elsif ( $obj->{$subject->{attributeDesc}} eq $subject->{assertionValue}) {
         return 1;
      }
      return 0;
    }

    default { warn "Unknown command: $cmd[0]\n" }
  }
  
  return;
}

1;
