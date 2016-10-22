#!perl -T

use Test::More tests => 3;

BEGIN {
    use_ok( 'Covetel::LDAP' ) || print "Bail out!\n";
    use_ok( 'Covetel::LDAP::AD' ) || print "Bail out!\n";
    use_ok( 'Covetel::LDAP::OpenLDAP' ) || print "Bail out!\n";
}

diag( "Testing Covetel::LDAP $Covetel::LDAP::VERSION, Perl $], $^X" );
