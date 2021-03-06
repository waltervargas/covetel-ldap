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
		'Config::Any::Base'       => '0',
		'Config::Tiny'            => '0',
		'Convert::ASN1::IO'       => '0',
		'Convert::ASN1::_decode'  => '0',
		'Convert::ASN1::_encode'  => '0',
		'Convert::ASN1::parser'   => '0',
		'Config::Any::INI'        => '0',
		'common::sense'           => '0',
		'Unicode::Map8'           => '0',
		'Net::LDAPS'              => '0',
		'Net::LDAP::Entry'        => '0',
		'Unicode::String'         => '0',
		'Encode::Alias'           => '0',
		'Encode::Config'          => '0',
		'Encode::Encoding'        => '0',
		'Storable'                => '0',
		'Encode::MIME::Name'      => '0',
		'Socket6'                 => '0',
		'URI::_query'             => '0',
		'URI::Find'               => '0',
		'URI::_punycode'          => '0',
		'URI::mailto'             => '0',
		'URI::Heuristic'          => '0',
		'URI::data'               => '0',
		'URI::Find::Schemeless'   => '0',
		'URI::QueryParam'         => '0',
		'URI::Split'              => '0',
		'URI::URL'                => '0',
		'URI::_foreign'           => '0',
		'URI::_segment'           => '0',
		'URI::file::FAT'          => '0',
		'URI::file::Mac'          => '0',
		'URI::file::OS2'          => '0',
		'URI::file::QNX'          => '0',
		'URI::ftp'                => '0',
		'URI::gopher'             => '0',
		'URI::https'              => '0',
		'URI::ldapi'              => '0',
		'URI::ldaps'              => '0',
		'URI::mms'                => '0',
		'URI::nntp'               => '0',
		'URI::pop'                => '0',
		'URI::rlogin'             => '0',
		'URI::rsync'              => '0',
		'URI::rtspu'              => '0',
		'URI::sips'               => '0',
		'URI::snews'              => '0',
		'URI::ssh'                => '0',
		'URI::telnet'             => '0',
		'URI::tn3270'             => '0',
		'URI::file'               => '0',
		'URI::_idna'              => '0',
		'URI::sip'                => '0',
		'URI::news'               => '0',
		'URI::_ldap'              => '0',
		'Net::LDAP::Bind'         => '0',
		'Net::LDAP::Extension'    => '0',
		'Net::LDAP::RootDSE'      => '0',
		'Net::LDAP::Schema'       => '0',
		'Net::LDAP::Search'       => '0',
		'Convert::ASN1::Debug'    => '0',
		'IO::Socket::INET6'       => '0',
		'Convert::ASN1'           => '0',
		'Net::LDAP::Filter'       => '0',
		'Net::LDAP::Message'      => '0',
		'Net::LDAP::ASN'          => '0',
		'Net::LDAP::Constant'     => '0',
		'Encode'                  => '0',
		'Net::LDAP::LDIF'         => '0',
		'Net::LDAP::Control'      => '0',
		'Net::LDAP::Util'         => '0',
		'Net::LDAP::Intermediate' => '0',
		'Net::LDAP'               => '0',
		'Unicode::CharName'       => '0',
		'MIME::Base64'            => '0',
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Covetel-LDAP-*' },
);
