#!/usr/bin/perl

package Catalyst::Plugin::Authorization::ACL;
use base qw/Class::Data::Inheritable/;

use strict;
use warnings;

use Scalar::Util ();
use Catalyst::Plugin::Authorization::ACL::Engine;

BEGIN { __PACKAGE__->mk_classdata("_acl_engine") }

our $VERSION = "0.01";

sub execute {
    my ( $c, $class, $action ) = @_;

	local $NEXT::NEXT{$c, "execute"};

    if ( Scalar::Util::blessed($action) ) {
		eval { $c->_acl_engine->check_action_rules( $c, $action ) };

		if ( my $err = $@ ) {
			return $c->acl_access_denied( $class, $action, $err );
		} else {
			$c->acl_access_allowed( $class, $action );
		}
		
    }

    $c->NEXT::execute( $class, $action );
}

sub setup {
    my $app = shift;
    my $ret = $app->NEXT::setup( @_ );

    $app->_acl_engine( Catalyst::Plugin::Authorization::ACL::Engine->new($app) );
    
    $ret;
}

sub deny_access_unless {
    my $c = shift;
    $c->_acl_engine->add_deny( @_ );
}

sub allow_access_if {
    my $c = shift;
    $c->_acl_engine->add_allow( @_ );
}

sub acl_add_rule {
    my $c = shift;
    $c->_acl_engine->add_rule( @_ );
}

sub acl_access_denied {
	my ( $c, $class, $action, $err ) = @_;
	
	if ( my $handler = ( $c->get_actions( "access_denied" , $action->namespace ) )[-1] ) {
		$handler->execute( $c );
	} else {
		return $c->execute( $class, sub { die $err });
	}
}

sub acl_access_allowed {

}

__PACKAGE__;

__END__

=pod

=head1 NAME

Catalyst::Plugin::Authorization::ACL - ACL support for L<Catalyst> applications.

=head1 SYNOPSIS

	use Catalyst qw/
		Authentication
		Authorization::Roles
		Authorization::ACL
	/;

	__PACKAGE__->setup;

	__PACKAGE__->deny_access_unless(
		"/foo/bar",
		[qw/nice_role/],
	);

	__PACKAGE__>allow_access_if(
		"/foo/bar/gorch",
		sub { return $boolean },
	);

=head1 DESCRIPTION

This module provide Access Control Lists with arbitrary rules for L<Catalyst>
applications. It operates on the L<Catalyst> private namespace, at least for
the mean while.

The two hierarchies of actions and controllers in L<Catalyst> are:

=over 4

=item Private Namepsace

Every action has it's own private path. This path reflects the Perl namespaces
the actions were born in, and the namespaces of their controllers.

=item External namespace

Some actions are also accessible from the outside, via another path.

This path is usually the same, if you used C<Local>. Alternatively you can use
C<Path>, C<Regex>, or C<Global> to specify a different external path for your
action.

=back

The ACL module currently only knows to exploit the private namespace. In the
future extensions may be made to support external namespaces as well.

=head1 METHODS

=item allow_access_if $path, $predicate

Check the predicate condition and allow access to the actions under C<$path> if
the predicate is true.

This is normally useful to allow acces only to a specific part of a tree whose
parent has a C<deny_access_unless> clause attached to it.

If the predicate condition is false access is not denied or allowed. Instead
the next rule will be checked - in this sense the combinatory behavior of these
rules is like logical B<OR>.

=item deny_access_unless $path, $predicate

Check the predicate condition and disallow access if the predicacte is false.

This is normally useful to restrict access to any portion of the application
unless a certain condition can be met.

If the predicate condition is true access is not allowed or denied. Instead the
next rule will be checked - in this sense the combinatory behavior of these
rules is like logical B<AND>

=item acl_add_rule $path, $rule, [ $filter ]

Manually add a rule to all the actions under C<$path> using the more flexible (but
more verbose) method:

	__PACKAGE__->acl_add_rule(
		"/foo",
		sub { ... }, # see FLEXIBLE RULES below
		sub {
			my $action = shift;
			# return a true value if you want to apply the rule to this action
			# called for all the actions under "/foo"
		}
	};

In this case the rule must be a sub reference (or method name) to be invoked on
$c.

The default filter will skip all actions starting with an underscore, namely
C<_DISPATCH>, C<_AUTO>, etc (but not C<auto>, C<begin>, et al).

=item RULE EVALUATION

When a rule is attached to an action the "distance" from the path it was
specified in is recorded. The closer the path is to the rule, the earlier it
will be checked.

Any rule can either explicitly deny or explicitly allow access to a particular
action. If a rule does not explicitly allow or permit access, the next rule is
checked, until the list of rules is finished. If no rule has determined a
policy, action to the controller will be permitted.

=item PATHS

To apply a rule to an action or group of actions you must supply a path.

This path is what you should see dumped at the begining of the L<Catalyst>
server's debug output.

For example, for the C<foo> action defined at the root level of your
applycation, specify C</foo>. Under the C<Moose> controller (e.g.
C<MyApp::C::Moose>, the action C<bar> will be C</moose/bar>).

The "distance" a path has from an action that is contained in it is the the
difference in the number of slashes between the path of the action, and the
path to which the rule was applied.

=item EASY RULES

There are several kinds of rules you can create without using the complex
interface described in L</FLEXIBLE RULES>.

The easy rules are all predicate list oriented. C<allow_access_if> will
explicitly allow access if the predicate is true, and C<deny_access_unless>
will explicitly disallow if the predicate is false.

=over 4

=item Role Lists

	__PACAKGE__->deny_access_unless( "/foo/bar", [qw/admin moose_trainer/] );

When the role is evaluated the L<Catalyst::Plugin::Authorization::Roles> will
be used to check whether the currently logged in user has the specified roles.

If C<allow_access_if> is used, the presence of B<all> the roles will
immediately permit access, and if C<deny_access_unless> is used the lack of
B<any> of the roles will immediately deny access.

When specifying a role list without the
L<Catalyst::Plugin::Authorization::Roles> plugin loaded the ACL engine will
throw an error.

=item Predicate Code Reference / Method Name

The code reference or method is invoked with the context and the action
objects. The boolean return value will determine the behavior of the rule.

	__PACKAGE__->allow_access_if( "/gorch", sub { ... } );
	__PACKAGE__->deny_access_unless( "/moose", "method_name" );

When specifying a method name the rule engine ensures that it can be invoked
uising L<UNIVERSAL/can>.

=back

=item FLEXIBLE RULES

These rules are the most annoying to write but provide the most flexibility.

All access control is performed using exceptions -
C<$Catalyst::Plugin::Authorization::ACL::Engine::DENIED>, and
C<$Catalyst::Plugin::Authorization::ACL::Engine::ALLOWED> (these can be
imported from the engine module).

If no rule decided to explicitly allow or disallow access, access will be
permitted.

Here is a rule that will always end the rule list by either explicitly allowing
or denying access based on how much mojo the current user has:

	__PACKAGE__->acl_add_rule(
		"/foo",
		sub {
			my ( $c, $action ) = @_;	
			
			if ( $c->user->mojo > 50 ) {
				die $ALLOWED;
			} else {
				die $DENIED;
			}
		}
	);

=head1 SEE ALSO

L<Catalyst::Plugin::Authentication>, L<Catalyst::Plugin::Authorization::Roles>

=head1 AUTHOR

Yuval Kogman, C<nothingmuch@woobling.org>

=head1 COPYRIGHT & LICNESE

	Copyright (c) 2005 the aforementioned authors. All rights
	reserved. This program is free software; you can redistribute
	it and/or modify it under the same terms as Perl itself.

=cut


