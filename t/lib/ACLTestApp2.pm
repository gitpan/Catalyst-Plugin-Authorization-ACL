package ACLTestApp2;

use strict;
use warnings;
no warnings 'uninitialized';

use Catalyst qw/
  Authorization::ACL
  /;

sub foo : Local {
    my ( $self, $c ) = @_;
    $c->res->body( $c->res->body . "foo");
}

sub bar : Local {
    my ( $self, $c ) = @_;
    $c->res->body( $c->res->body . "bar");
}

sub gorch : Local {
    my ( $self, $c, $frozjob ) = @_;
    $c->res->body( $c->res->body . "gorch");
    $c->res->body( $c->res->body . "&frozjob=$frozjob");
}

sub end : Private {
    my ( $self, $c ) = @_;

    $c->res->body( join " ",
        ( $c->stash->{denied} || @{ $c->error } ? "denied" : "allowed" ),
        $c->res->body );
}

sub access_denied : Private {
    my ( $self, $c, $action, $error ) = @_;

    $c->res->header( 'X-Catalyst-ACL-Param-Action' => $action->reverse, 'X-Catalyst-ACL-Param-Error' => $error );
    $c->res->body( join " ", "handled", $c->res->body );

    $c->stash->{denied} = 1;

    $c->forcibly_allow_access if $c->action->name eq "gorch";
}

__PACKAGE__->setup;

__PACKAGE__->deny_access("/");

__PACKAGE__->allow_access("/bar");

