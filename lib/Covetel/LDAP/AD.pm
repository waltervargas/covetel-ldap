package Covetel::LDAP::AD;

use common::sense;
use parent qw(Covetel::LDAP);
use Net::LDAPS;
use Net::LDAP::Entry;
use Unicode::Map8;
use Unicode::String qw(utf16);
use Net::LDAP::Control::Paged;
use Net::LDAP::Constant qw( LDAP_CONTROL_PAGED );
use Data::Dumper;

=head1 NAME

Covetel::LDAP::AD - Active Directory Operations

=head1 VERSION

Version 0.07

=cut

our $VERSION = '0.07';

=head1 SYNOPSIS

    my $ad = Covetel::AD->new;

        if($ad->bind){

            my $result = $ad->search_user('user01');

            if ($result->count > 0){
                my $entry = $result->shift_entry();
                $entry->dump();
            }

        } else {
            die $ad->{mesg}->error_desc();
        }


=head1 SUBROUTINES/METHODS

=head2 new

=cut

sub new {
    my $class = shift;
    my $self  = $class->SUPER::new;

    my $options = shift;

    my $cnf_file = $options->{'config'} // 'ad.ini';

    my $config = $self->config($cnf_file);

    $self->{config} = $config;

    my $LDAP = $config->{ldap}->{tls} ? 'Net::LDAPS' : 'Net::LDAP';

    $self->{'server'} = $LDAP->new(
        $config->{'ldap'}->{'host'},
        port   => $config->{'ldap'}->{'port'},
        verify => 'none',
    ) || die $@;

    bless $self, $class;
    return $self;
}

=head2 bind

    if($ad->bind){
        # do something
    } else {
        die $ad->{mesg}->error_desc();
    }

=cut

sub bind {
    my $self = shift;
    my $mesg = $self->{server}->bind( $self->{'config'}->{'ldap'}->{'user'},
        password => $self->{'config'}->{'ldap'}->{'passwd'} );
    $self->{mesg} = $mesg;
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

=head2 base_group

Return base for group entries

=cut

sub base_group {
    my $self = shift;

    my $base       = $self->{'config'}->{'ldap'}->{'base'};
    my $group_rdn = $self->{'config'}->{'ldap'}->{'groups_rdn'};
    if ($group_rdn) {
        return $group_rdn . ',' . $base;
    }
    else {
        return $base;
    }
}

=head2 base_list

Return base for lists entries

=cut

sub base_list {
    my $self = shift;

    my $base       = $self->{'config'}->{'ldap'}->{'base'};
    my $list_rdn = $self->{'config'}->{'ldap'}->{'lists_rdn'};
    if ($list_rdn) {
        return $list_rdn . ',' . $base;
    }
    else {
        return $base;
    }
}

=head2 search

    my $result = $self->search({filter => "(sAMAccountName=$uid)"});

=cut

sub search {
    my ( $self, $options ) = @_;
    my ( $base, $attrs, $filter, $control );

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
        attrs  => $attrs
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

    my $result = $ad->search_user('user01');

=cut

sub search_user {
    my ( $self, $uid ) = @_;

    my $result = $self->search( { filter => "(sAMAccountName=$uid)" } );

    return $result;
}

=head2 users

Return a list of Net::LDAP::Entry

=cut

sub users {
    my $self = shift;

    my $result = $self->search( { filter => "(objectClass=User)" } );
    if ( $result->count > 0 ) {
        return $result->entries;
    }
    else {
        return ();
    }

}

=head2 add_user

    my $result = $ad->add_user(
        {
            firstname => 'Pedro',
            lastname  => 'Perez',
            mail      => 'pperez@example.com',
            uid       => 'pperez',
        }
    );

=cut

sub add_user {
    my ( $self, $attrs ) = @_;

    my $dn = 'CN='
      . $attrs->{'firstname'} . ' '
      . $attrs->{'lastname'} . ','
      . $self->base_people;

    my $entry = Net::LDAP::Entry->new;

    $entry->dn($dn);

    $entry->add(
        objectClass => [ 'top', 'person', 'organizationalPerson', 'user' ],
        cn                => $attrs->{'firstname'} . ' ' . $attrs->{'lastname'},
        sn                => $attrs->{'lastname'},
        givenName         => $attrs->{'firstname'},
        sAMAccountName    => $attrs->{'uid'},
        userPrincipalName => $attrs->{'mail'},
        mail              => $attrs->{'mail'},
        userAccountControl => 512,
        displayName => $attrs->{'firstname'} . ' ' . $attrs->{'lastname'},
        name        => $attrs->{'firstname'} . ' ' . $attrs->{'lastname'},
    );

    $entry->add(
        unicodePwd => $self->_prepare_password( $attrs->{'password'} ) )
      if $attrs->{'password'};

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

    my $charmap = Unicode::Map8->new('latin1') or die;
    my $password =
      $charmap->tou( '"' . $plain_text . '"' )->byteswap()->utf16();

    return $password;
}

=head2 del_user

Method for delete an user.

=cut

sub del_user {
    my ( $self, $uid ) = @_;

    my $resp = $self->search( { filter => "(sAMAccountName=$uid)" } );
    my $entry = $resp->shift_entry if $resp->count > 0;
    my $mesg = $self->{'server'}->delete( $entry->dn );

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
    $entry->replace( unicodePwd => $self->_prepare_password($clear), );
    my $mesg = $entry->update( $self->{server} );
    $self->{'mesg'} = $mesg;
    if ( $mesg->is_error ) {
        return 0;
    }
    else {
        return 1;
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

    perldoc Covetel::LDAP::AD


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

1;    # End of Covetel::LDAP::AD
