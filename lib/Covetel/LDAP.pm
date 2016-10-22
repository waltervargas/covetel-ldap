package Covetel::LDAP;

use common::sense;
use Config::Any::INI;

=head1 NAME

Covetel::LDAP - Covetel::LDAP base class

=head1 VERSION

Version 0.07

=cut

our $VERSION = '0.07';

=head1 SYNOPSIS

    use Covetel::LDAP;

    my $ldap = Covetel::LDAP->new();

=head1 SUBROUTINES/METHODS

=head2 new

=cut

sub new {
    my $class = shift;
    my $self  = {};
    bless $self, $class;
    return $self;
}

=head2 config

Return config hash

=cut

sub config {
    my $self        = shift;
    my $config_file = shift;

    my $config = Config::Any::INI->load($config_file);

    return $config;
}

=head1 AUTHOR

Walter Vargas, C<< <wvargas at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-covetel-ldap at
rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Covetel-LDAP>.  I
will be notified, and then you'll automatically be notified of
progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Covetel::LDAP


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

1;    # End of Covetel::LDAP
