use Module::Build;
my $build = Module::Build->new
    (
     module_name => 'FlatLdap',
     license  => 'perl',
     requires => {
                  'perl'              => '5.10.0',
                  'Net::LDAP'         => '0.36',
                  'Net::LDAP::Server' => '0.4',
                 },
    );
$build->create_build_script;
