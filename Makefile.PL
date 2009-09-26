use inc::Module::Install 0.91;

if ( -e 'MANIFEST.SKIP' ) {
    system( 'pod2text lib/Catalyst/Plugin/Authorization/ACL.pm > README' );
}

perl_version '5.008';

name 'Catalyst-Plugin-Authorization-ACL';
all_from 'lib/Catalyst/Plugin/Authorization/ACL.pm';

test_requires 'Test::More';
test_requires 'Catalyst::Plugin::Session';
test_requires 'Catalyst::Plugin::Session::State::Cookie';
test_requires 'Test::WWW::Mechanize::Catalyst';

requires 'Catalyst::Runtime' => '5.80013';
requires 'Catalyst::Plugin::Authentication';
requires 'Catalyst::Plugin::Authorization::Roles';
requires 'Moose';
requires 'MRO::Compat';
requires 'namespace::autoclean';
requires 'Class::Data::Inheritable';
requires 'Class::Throwable';
requires 'Tree::Simple';
requires 'Tree::Simple::Visitor::FindByPath';
requires 'Tree::Simple::Visitor::GetAllDescendents';

resources repository => 'http://dev.catalyst.perl.org/repos/Catalyst/trunk/Catalyst-Plugin-Authorization-ACL/';

auto_provides;
auto_install;
WriteAll;
