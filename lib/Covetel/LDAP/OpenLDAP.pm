package Covetel::LDAP::OpenLDAP;

use common::sense;
use parent qw(Covetel::LDAP);
use Net::LDAPS;
use Net::LDAP::Entry;
use Digest::SHA1 qw(sha1_base64);
use Data::Dumper;
use Scalar::Util qw(blessed);
use Net::LDAP::Control::Paged;
use Net::LDAP::Constant qw( LDAP_CONTROL_PAGED );

=head1 NAME

Covetel::LDAP::OpenLDAP - OpenLDAP Operations

=head1 VERSION

Version 0.07

=cut

our $VERSION = '0.07';

=head1 SYNOPSIS

    my $openldap = Covetel::OpenLDAP->new;

        if($openldap->bind){

            my $result = $openldap->search_user('user01');

            if ($result->count > 0){
                my $entry = $result->shift_entry();
                $entry->dump();
            }

        } else {
            die $openldap->{mesg}->error_desc();
        }


=head1 SUBROUTINES/METHODS

=head2 new

=cut

sub new {
    my $class = shift;
    my $self  = $class->SUPER::new;

    my $options = shift;

    my $cnf_file = $options->{'config'} // 'openldap.ini';

    my $config = $self->config($cnf_file);

    my $self->{'config'} = $config;

    my $LDAP = $config->{'ldap'}->{'tls'} ? 'Net::LDAPS' : 'Net::LDAP';

    $self->{'server'} = $LDAP->new(
        $config->{'ldap'}->{'host'},
        port   => $config->{'ldap'}->{'port'},
        verify => 'none',
    ) || die $@;

    $self->{'ldap'} = $self->{'server'};

    bless $self, $class;
    return $self;
}

=head2 bind

    if($openldap->bind){
        # do something
    } else {
        die $openldap->{mesg}->error_desc();
    }

=cut

sub bind {
    my $self = shift;
    my $mesg = $self->{server}->bind( $self->{'config'}->{'ldap'}->{'user'},
        password => $self->{'config'}->{'ldap'}->{'passwd'} );
    $self->{'mesg'} = $mesg;
    if ( $mesg->is_error ) {
        return 0;
    }
    else {
        return 1;
    }
}

=head2 base

Return search base from config file

=cut

sub base {
    my $self = shift;

    my $base = $self->{'config'}->{'ldap'}->{'base'};

    return $base;
}

=head2 base_people

Return base for people entries

=cut

sub base_people {
    my $self = shift;

    my $base       = $self->{'config'}->{'ldap'}->{'base'};
    my $people_rdn = $self->{'config'}->{'ldap'}->{'people_rdn'};
    if ($people_rdn) {
        return $people_rdn . ',' . $base;
    }
    else {
        return $base;
    }
}

=head2 base_maintenance

return base mantenimiento 

=cut 

sub base_maintenance {
    my $self = shift;

    my $base = $self->{'config'}->{'ldap'}->{'base'};
    my $rdn  = $self->{'config'}->{'ldap'}->{'maintenance_rdn'};
    if ($rdn) {
        return $rdn . ',' . $base;
    }
    else {
        return $base;
    }
}

=head2 base_group

Return base for group entries

=cut

sub base_group {
    my $self = shift;

    my $base       = $self->{'config'}->{'ldap'}->{'base'};
    my $group_rdn  = $self->{'config'}->{'ldap'}->{'groups_rdn'};
    my $base_group = $group_rdn . ',' . $base;

    return $base_group;
}

=head2 base_list

Return base for list entries

=cut

sub base_list {
    my $self = shift;

    my $base       = $self->{'config'}->{'ldap'}->{'base'};
    my $list_rdn  = $self->{'config'}->{'ldap'}->{'lists_rdn'};
    my $base_list = $list_rdn . ',' . $base;

    return $base_list;
}

=head2 base_aliases

Return base for aliases entries

=cut

sub base_aliases {
    my $self = shift;

    my $base       = $self->{'config'}->{'ldap'}->{'base'};
    my $aliases_rdn  = $self->{'config'}->{'ldap'}->{'aliases_rdn'};
    my $base_aliases = $aliases_rdn . ',' . $base;

    return $base_aliases;
}

=head2 search

    my $result = $self->search({filter => "(uid=$uid)"});

=cut

sub search {
    my ( $self, $options ) = @_;
    my ( $base, $attrs, $filter );

    #the base of the search.
    if ( !$options->{'base'} ) {
        $base = $self->base();
    }
    else {
        $base = $options->{'base'};
    }

    my $scope = $options->{'scope'} // 'sub';

    # attrs list.
    if ( !$options->{'attrs'} ) {
        $attrs = ['*'];
    }
    else {
        $attrs = $options->{'attrs'};
    }

    # default filter
    if ( !$options->{'filter'} ) {
        $filter = '';
    }
    else {
        $filter = $options->{'filter'};
    }

    my $result = $self->{server}->search(
        base   => $base,
        scope  => $scope,
        filter => $filter,
        attrs => ref $attrs eq 'ARRAY' ? $attrs : [$attrs],
    );
    return $result;
}

=head2 paged_search

    my $result = $self->paged_search({filter => "(sAMAccountName=$uid)"});

=cut

sub paged_search {
    my ( $self, $options ) = @_;
    my ( $base, $attrs, $filter, $control );

    #the base of the search.
    if ( !$options->{'base'} ) {
        $base = $self->base();
    }
    else {
        $base = $options->{'base'};
    }

    my $scope = $options->{'scope'};

    # attrs list.
    if ( !$options->{'attrs'} ) {
        $attrs = ['*'];
    }
    else {
        $attrs = $options->{'attrs'};
    }

    # default filter
    if ( !$options->{'filter'} ) {
        $filter = '';
    }
    else {
        $filter = $options->{'filter'};
    }

    # default control
    if ( !$options->{'control'} ) {
        $control = '';
    }
    else {
        $control = $options->{'control'};
    }

    my $cookie;
    my @entries;

    my $full_result;
    while (1) {

        my $result = $self->{server}->search(
            base    => $base,
            scope   => $scope,
            filter  => $filter,
            control => $control,
            attrs   => $attrs
        );

        $full_result = $result;

        if ( $full_result->is_error ) {
            return $full_result;
        }
        push( @entries, @{ $result->{entries} } );

        # Get cookie from paged control
        my ($resp) = $result->control(LDAP_CONTROL_PAGED) or last;
        $cookie = $resp->cookie or last;

        # Set cookie in paged control
        $control->cookie($cookie);

    }

    if ($cookie) {

       # We had an abnormal exit, so let the server know we do not want any more
        $control->cookie($cookie);
        $control->size(0);
        $self->{server}->search(
            base    => $base,
            scope   => $scope,
            filter  => $filter,
            control => $control,
            attrs   => $attrs
        );
    }
    $full_result->{entries} = \@entries;

    return $full_result;
}

=head2 search_user

    my $result = $openldap->search_user('user01');

=cut

sub search_user {
    my ( $self, $uid ) = @_;

    my $mesg = $self->search( { filter => "(uid=$uid)" } );

    $self->{mesg} = $mesg;

    if ( $mesg->count == 0 ) {
        return 0;
    }
    else {
        return $mesg->shift_entry;
    }

}

=head2 add_entry

Create a entry user with given attributes

=cut

sub add_entry {
    my ( $self, $attrs ) = @_;

    $self->add_user($attrs);
}

=head2 add_user

Method for create an user in the openldap

=cut

sub add_user {
    my ( $self, $attrs ) = @_;
    my $dn = $attrs->{'dn'}
      // 'uid=' . $attrs->{'uid'} . ',' . $self->base_people;

    delete $attrs->{'dn'};

    my $entry = Net::LDAP::Entry->new;

    $entry->dn($dn);

    if ( $attrs->{'objectClass'} ) {
        $entry->add( objectClass => $attrs->{'objectClass'} );
        delete $attrs->{'objectClass'};
    }
    else {
        $entry->add( objectClass =>
              [ 'top', 'person', 'organizationalPerson', 'inetOrgPerson' ], );
    }

    if ( $attrs->{'userPassword'} ) {
        $entry->add(
            userPassword => $self->_prepare_password( $attrs->{'password'} ) );
        delete $attrs->{'userPassword'};
    }

    for ( keys %{$attrs} ) {
        $entry->add( $_ => $attrs->{$_} );
    }

    my $mesg = $self->{'server'}->add($entry);

    $self->{mesg} = $mesg;

    if ( $mesg->is_error ) {
        return 0;
    }
    else {
        return 1;
    }
}

=head2 _prepare_password

Internal method for preparing password

=cut

sub _prepare_password {
    my ( $self, $plain_text ) = @_;
    my $p = sha1_base64($plain_text);
    $p = "{SHA}" . $p . "=";
    return $p;
}

=head2 del_user

Method for delete an user.

=cut

sub del_user {
    my ( $self, $uid ) = @_;

    my $resp = $self->search( { filter => "(uid=$uid)" } );
    my $entry = $resp->shift_entry if $resp->count > 0;
    my $mesg = $self->{'server'}->delete( $entry->dn );

    $self->{'mesg'} = $mesg;

    if ( $mesg->is_error ) {
        return 0;
    }
    else {
        return 1;
    }
}

=head2 create_ou

Create a OrganizationalUnit

  create_ou(
    'Personas',
    {
      base => 'dc=covetel,dc=com,dc=ve',
      description => 'Rama de personas'
    }
  );

=cut

sub create_ou {
    my ( $self, $ou, $options ) = @_;

    my $base = $options->{'base'}        // $self->base;
    my $desc = $options->{'description'} // ' ';

    my $dn = 'ou=' . $ou . ',' . $base;

    my $mesg = $self->{'server'}->add(
        $dn,
        attrs => [
            ou          => $ou,
            description => $desc,
            objectClass => ['organizationalUnit'],
        ]
    );
    $self->{mesg} = $mesg;

    if ( $mesg->is_error ) {
        return 0;
    }
    else {
        return 1;
    }
}

=head2 change_password

Change password for an entry

=cut

sub change_password {

    my ( $self, $uid, $clear ) = @_;
    my $r = $self->search_user($uid);
    my $entry = $r->shift_entry if $r->count > 0;
    $entry->replace( userPassword => $self->_prepare_password($clear), );
    my $mesg = $entry->update( $self->{server} );
    $self->{'mesg'} = $mesg;
    if ( $mesg->is_error ) {
        return 0;
    }
    else {
        return 1;
    }
}

sub add_other_password {
    my ( $self, $password, $uid ) = @_;

    my $user;

    if ( !blessed $uid) {
        $user = $self->search_user($uid);
    }
    else {
        $user = $uid;
    }

    my $passwords =
      $user->get_value( 'userPassword', alloptions => 1, asref => 1 );

    if ($passwords) {
        $passwords = $passwords->{""};
    }

    my $newpass = $self->_prepare_password($password);

    # if user doesnt has the password already
    if ( !( grep $_ eq $newpass, @{$passwords} ) ) {
        push @{$passwords}, $newpass;
    }
    else {
        return 1;
    }

    $user->replace( "userPassword" => $passwords );

    my $mesg = $user->update( $self->{server} );
    $self->{'mesg'} = $mesg;

    if ( $mesg->is_error ) {
        return 0;
    }
    else {
        return 1;
    }
}

=head2 get_maintenance_user

return maintenance user

=cut 

sub get_maintenance_user {
    my $self = shift;

    $self->{mesg} = $self->search(
        {
            base   => $self->base_maintenance,
            filter => '(objectClass=posixAccount)',
        }
    );

    if ( $self->{mesg}->count ) {
        return $self->{mesg}->shift_entry;
    }
    else {
        return 0;
    }

}

=head2 get_maintenance_uidNumber

Return uidNumber of maintenance user

=cut 

sub get_maintenance_uidNumber {
    my $self = shift;

    my $muser = $self->get_maintenance_user;

    if ($muser) {
        return $muser->get_value('uidNumber');
    }
    else {
        return 0;
    }
}

=head2 set_maintenance_uidNumber

Set uidNumber of maintenance user

=cut 

sub set_maintenance_uidNumber {
    my $self      = shift;
    my $uidNumber = shift;

    my $muser = $self->get_maintenance_user;

    if ($muser) {

        $muser->replace( uidNumber => $uidNumber );

        my $mesg = $muser->update( $self->{server} );

        $self->{'mesg'} = $mesg;

        if ( $mesg->is_error ) {
            return 0;
        }
        else {
            return 1;
        }
    }
    else {
        return 0;
    }
}

=head2 increase_maintenance_uidNumber

Increase uidNumber of maintenance user

=cut 

sub increase_maintenance_uidNumber {
    my $self = shift;

    my $uidNumber = $self->get_maintenance_uidNumber;

    if ($uidNumber) {

        $uidNumber++;

        if ( $self->set_maintenance_uidNumber($uidNumber) ) {
            return 1;
        }
        else {
            return 0;
        }
    }
    else {
        return 0;
    }

}

=head2 decrease_maintenance_uidNumber

Decrease uidNumber of maintenance user

=cut 

sub decrease_maintenance_uidNumber {
    my $self = shift;

    my $uidNumber = $self->get_maintenance_uidNumber;

    if ($uidNumber) {

        $uidNumber--;

        if ( $self->set_maintenance_uidNumber($uidNumber) ) {
            return 1;
        }
        else {
            return 0;
        }
    }
    else {
        return 0;
    }

}

=head2 get_people_gidNumber

Return people gidNumber from config file

=cut

sub get_people_gidNumber {

    my $self = shift;
    return $self->{'config'}->{'ldap'}->{'people_gidNumber'};

}

=head2 get_maintenance_gidNumber

Return gidNumber of maintenance user

=cut 

sub get_maintenance_gidNumber {
    my $self = shift;

    my $mgroup = $self->get_maintenance_user;

    if ($mgroup) {
        return $mgroup->get_value('gidNumber');
    }
    else {
        return 0;
    }
}

=head2 set_maintenance_gidNumber

Set gidNumber of maintenance group

=cut 

sub set_maintenance_gidNumber {
    my $self      = shift;
    my $gidNumber = shift;

    my $mgroup = $self->get_maintenance_user;

    if ($mgroup) {

        $mgroup->replace( gidNumber => $gidNumber );

        my $mesg = $mgroup->update( $self->{server} );

        $self->{'mesg'} = $mesg;

        if ( $mesg->is_error ) {
            return 0;
        }
        else {
            return 1;
        }
    }
    else {
        return 0;
    }
}

=head2 increase_maintenance_gidNumber

Increase gidNumber of maintenance group

=cut 

sub increase_maintenance_gidNumber {
    my $self = shift;

    my $gidNumber = $self->get_maintenance_gidNumber;

    if ($gidNumber) {

        $gidNumber++;

        if ( $self->set_maintenance_gidNumber($gidNumber) ) {
            return 1;
        }
        else {
            return 0;
        }
    }
    else {
        return 0;
    }

}

=head2 decrease_maintenance_gidNumber

Decrease gidNumber of maintenance group

=cut 

sub decrease_maintenance_gidNumber {
    my $self = shift;

    my $gidNumber = $self->get_maintenance_gidNumber;

    if ($gidNumber) {

        $gidNumber--;

        if ( $self->set_maintenance_gidNumber($gidNumber) ) {
            return 1;
        }
        else {
            return 0;
        }
    }
    else {
        return 0;
    }

}

=head1 AUTHOR

Walter Vargas, C<< <wvargas at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-covetel-ldap at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Covetel-LDAP>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.


=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Covetel::LDAP::OpenLDAP

You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Covetel-LDAP>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Covetel-LDAP>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Covetel-LDAP>

=item * Search CPAN

L<http://search.cpan.org/dist/Covetel-LDAP/>

=back

=head1 ACKNOWLEDGEMENTS

=head1 LICENSE AND COPYRIGHT

Copyright 2011 Walter Vargas.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1;    # End of Covetel::LDAP::OpenLDAP
