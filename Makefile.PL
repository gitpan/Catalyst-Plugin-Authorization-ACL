use inc::Module::Install 0.77;

if ( -e 'MANIFEST.SKIP' ) {
    system( 'pod2text lib/Catalyst/Plugin/Authorization/ACL.pm > README' );
}

perl_version '5.008';

name 'Catalyst-Plugin-Authorization-ACL';
all_from 'lib/Catalyst/Plugin/Authorization/ACL.pm';

requires 'Catalyst::Runtime' => '5.7000';
requires 'Class::Data::Inheritable';
requires 'Class::Throwable';
requires 'Tree::Simple::Visitor::FindByPath';
requires 'Tree::Simple::Visitor::GetAllDescendents';

test_requires 'Test::More';

WriteAll;
