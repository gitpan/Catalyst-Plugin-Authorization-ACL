use inc::Module::Install 0.91;

if ( -e 'MANIFEST.SKIP' ) {
    system( 'pod2text lib/Catalyst/Plugin/Authorization/ACL.pm > README' );
}

perl_version '5.008';

name 'Catalyst-Plugin-Authorization-ACL';
all_from 'lib/Catalyst/Plugin/Authorization/ACL.pm';

test_requires 'Test::More';
test_requires 'Catalyst::Plugin::Authentication';
test_requires 'Catalyst::Plugin::Authorization::Roles';
test_requires 'Catalyst::Plugin::Session';
test_requires 'Catalyst::Plugin::Session::State::Cookie';

requires 'Catalyst::Runtime' => '5.7000';
requires 'Class::Data::Inheritable';
requires 'Class::Throwable';
requires 'Tree::Simple::Visitor::FindByPath';
requires 'Tree::Simple::Visitor::GetAllDescendents';
requires 'MRO::Compat';

resources repository => 'http://dev.catalyst.perl.org/repos/Catalyst/trunk/Catalyst-Plugin-Authorization-ACL/';

auto_provides;
auto_install;
WriteAll;
