use Module::Build;
my $build = Module::Build->new
    (
     module_name => 'FlatLdap',
     license  => 'perl',
     requires => {
                  'perl'          => '5.6.1',
                 },
    );
$build->create_build_script;
