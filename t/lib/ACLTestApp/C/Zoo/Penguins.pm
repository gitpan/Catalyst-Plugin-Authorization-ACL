#!/usr/bin/perl

package ACLTestApp::C::Zoo::Penguins;
use base qw/Catalyst::Controller/;

use strict;
use warnings;

sub emperor : Local {
	my ( $self, $c ) = @_;
	$c->res->body("emperor penguin");
}

sub tux : Local {
	my ( $self, $c ) = @_;
	$c->res->body("tux");
}

sub madagascar : Local {
	my ( $self, $c ) = @_;
	$c->res->body("madagascar");
}

__PACKAGE__;

__END__

=pod

=head1 NAME

ACLTestApp::C::Zoo - 

=head1 SYNOPSIS

	use ACLTestApp::C::Zoo;

=head1 DESCRIPTION

=cut

