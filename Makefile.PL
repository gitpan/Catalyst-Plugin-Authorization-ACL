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

requires 'MRO::Compat';

if($] < 5.009_005) {
    requires 'Class::C3::XS' => '0.08';
    requires 'Class::C3' => '0.20';
}

test_requires 'Test::More';

WriteAll;
