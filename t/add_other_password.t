#!/usr/bin/env perl
use Test::Simple tests => 2;
use Covetel::LDAP::OpenLDAP;

my $ldap = Covetel::LDAP::OpenLDAP->new({config => 't/add_other_password.ini'});
my $user = 'wvargas';
my $pass = '123321...';

$ldap->bind // die "$ldap->{mesg}->error_text";

ok( $ldap->add_other_password($pass,$user), "Pasword Agregado al usuario $user");

my $entry = $ldap->search_user($user); 

ok( $ldap->{server}->bind( $entry->dn, $pass), "Bind con $user y $pass");
