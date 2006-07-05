package ACLTestApp;

use strict;
use warnings;
no warnings 'uninitialized';

use Catalyst qw/
	Session
	Session::Store::Dummy
	Session::State::Cookie

	Authentication
	Authentication::Store::Minimal
	Authentication::Credential::Password

	Authorization::Roles
	Authorization::ACL
/;

use Catalyst::Plugin::Authorization::ACL::Engine qw/$DENIED $ALLOWED/;

sub restricted : Local {
	my ( $self, $c ) = @_;
	$c->res->body( "restricted" );
}

sub default : Private {
	my ( $self, $c ) = @_;
	$c->res->body( "welcome to the zoo!" );
	
}

sub end : Private {
	my ( $self, $c ) = @_;
	$c->res->body( $c->res->body . ($c->error->[-1] =~ /denied/ ? "denied" : "allowed") );
	$c->error( 0 );
}

__PACKAGE__->config(
    authentication => {
        users => {
            foo => {
                password => "bar",
                os => "windows",
            },
            gorch => {
                password => "moose",
                roles => [qw/child/],
                os => "linux",
            },
            quxx => {
                password => "ding",
                roles => [qw/moose_trainer/],
                os => "osx",
            },
        },
    },
    acl => {
        deny => ["/restricted"],
    }
);

__PACKAGE__->setup;

__PACKAGE__->allow_access_if("/", sub { 1 }); # just to test that / can be applied to

__PACKAGE__->deny_access_unless("/lioncage", [qw/zoo_worker lion_tamer/]); # only highly trained personnel can enter

# this now in config
# __PACKAGE__->deny_access_unless("/restricted", sub { 0 }); # no one can access

__PACKAGE__->deny_access_unless("/zoo", sub {
	my ( $c, $action ) = @_;
	$c->user;
}); # only people who have bought a ticket can enter

__PACKAGE__->deny_access_unless("/zoo/rabbit", ["child"]); # the petting zoo is for children

__PACKAGE__->deny_access_unless("/zoo/moose", [qw/moose_trainer/]);

__PACKAGE__->acl_add_rule("/zoo/penguins/tux", sub {
	my ( $c, $action ) = @_;
	my $user = $c->user;
	die ( ( $user && $user->os eq "linux" ) ? $ALLOWED : $DENIED );
});

__PACKAGE__->allow_access_if("/zoo/penguins/madagascar", sub { 
	my ( $c, $action ) = @_;
	my $user = $c->user;
	$user && $user->os ne "windows";
});

__PACKAGE__
