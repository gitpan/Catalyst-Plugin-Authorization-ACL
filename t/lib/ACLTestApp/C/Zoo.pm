#!/usr/bin/perl

package ACLTestApp::C::Zoo;
use base qw/Catalyst::Controller/;

use strict;
use warnings;

sub moose : Local {
	my ( $self, $c ) = @_;
	$c->res->body("moose");
}

sub elk : Local {
	my ( $self, $c ) = @_;
	$c->res->body("elk ");
}

sub rabbit : Local {
	my ( $self, $c ) = @_;
	$c->res->body("rabbit ");
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


