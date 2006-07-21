use strict;
use Module::Build;

my $build = Module::Build->new(
    create_makefile_pl => 'traditional',
    license            => 'perl',
    module_name        => 'Catalyst::Plugin::Authorization::ACL',
    requires           => {
        'Catalyst' => '5.7',

        'Class::Data::Inheritable' => 0,

        'Class::Throwable'                         => 0,
        'Tree::Simple::Visitor::FindByPath'        => 0,
        'Tree::Simple::Visitor::GetAllDescendents' => 0,
    },
    create_readme => 1,
    sign          => 1,
);
$build->create_build_script;

