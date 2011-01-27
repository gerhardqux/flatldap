package FlatLdap::Search;

use warnings;
use strict;
use feature "switch";
use Data::Dumper;

use FlatLdap::Schema;

use vars qw( $schema );

sub new
{
	my ($class, $filter) = @_;

        $schema = new FlatLdap::Schema();

	return bless { filter => $filter }, $class;	
}

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

		when ('equalityMatch') {

			my @arr = grep { m/$subject->{attributeDesc}/ } @{$schema->{posixAccount}}, @{$schema->{posixGroup}}, 'objectClass';
			unless (@arr) {
				warn "Unknown key requested in attributeDesc: ".$subject->{attributeDesc}."\n";
				return 0;
			}

			if ($obj->{$subject->{attributeDesc}}) {
				if (ref($obj->{$subject->{attributeDesc}}) eq 'ARRAY') {
					for (@{$obj->{$subject->{attributeDesc}}}) {
						if ($_ eq $subject->{assertionValue}) {
							return 1;
						}
					}
				}
				elsif ( $obj->{$subject->{attributeDesc}} eq $subject->{assertionValue}) {
			   		return 1;
				}
			}
			return 0;
                }

		default { warn "Unknown command: $cmd[0]\n" }
	}
	
	return;
}

1;
