use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Covetel::LDAP',
    AUTHOR              => q{Walter Vargas <wvargas@cpan.org>},
    VERSION_FROM        => 'lib/Covetel/LDAP.pm',
    ABSTRACT_FROM       => 'lib/Covetel/LDAP.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Covetel-LDAP-*' },
);
