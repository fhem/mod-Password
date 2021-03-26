package FHEM::Core::Password::Utils;

use 5.008;

use strict;
use warnings;

use GPUtils qw(GP_Import);

## Import der FHEM Funktionen
#-- Run before package compilation
BEGIN {

    # Import from main context
    GP_Import(
        qw(
            Log3
            setKeyValue
            getKeyValue
            getUniqueId
            defs
          )
    );
}

### eigene Funktionen exportieren
require Exporter;
our @ISA       = qw(Exporter);
our @EXPORT_OK = qw(
                     new
                     setStorePassword
                     setDeletePassword
                     getReadPassword
                     setRename
);
our %EXPORT_TAGS = (
    ALL => [
        qw(
            new
            setStorePassword
            setDeletePassword
            getReadPassword
            setRename
          )
    ],
);


sub new {
    my $class = shift;
    my $self  = {
                  name  => undef,
                };

    bless $self, $class;
    return $self;
}

sub setStorePassword {
    my $self        = shift;
    my $name        = shift;
    my $password    = shift;

    my $index   = $defs{$name}->{TYPE} . '_' . $name . '_passwd';
    my $key     = getUniqueId() . $index;
    my $enc_pwd = '';

    if ( eval q{use Digest::MD5;1} ) {

        $key = Digest::MD5::md5_hex( unpack "H*", $key );
        $key .= Digest::MD5::md5_hex($key);
    }

    for my $char ( split /q{}/, $password ) {

        my $encode = chop($key);
        $enc_pwd .= sprintf( "%.2x", ord($char) ^ ord($encode) );
        $key = $encode . $key;
    }

    my $err = setKeyValue( $index, $enc_pwd );
    return qq{error while saving the password - $err}
      if ( defined($err) );

    return q{password successfully saved};
}

sub setDeletePassword {
    my $self = shift;
    my $name = shift;

    setKeyValue( $defs{$name}->{TYPE} . '_' . $name . '_passwd', undef );

    return;
}

sub getReadPassword {
    my $self    = shift;
    my $name    = shift;

    my $index   = $defs{$name}->{TYPE} . '_' . $name . '_passwd';
    my $key     = getUniqueId() . $index;
    my ( $password, $err );

    Log3($name, 4, qq{GardenaSmartBridge ($name) - Read password from file});

    ( $err, $password ) = getKeyValue($index);

    if ( defined($err) ) {

        Log3($name, 3,
qq{GardenaSmartBridge ($name) - unable to read password from file: $err});

        return undef;
    }

    if ( defined($password) ) {
        if ( eval q{use Digest::MD5;1} ) {

            $key = Digest::MD5::md5_hex( unpack "H*", $key );
            $key .= Digest::MD5::md5_hex($key);
        }

        my $dec_pwd = '';

        for my $char ( map { pack( 'C', hex($_) ) } ( $password =~ /(..)/g ) ) {

            my $decode = chop($key);
            $dec_pwd .= chr( ord($char) ^ ord($decode) );
            $key = $decode . $key;
        }

        return $dec_pwd;
    }
    else {

        Log3($name, 3, qq{GardenaSmartBridge ($name) - No password in file});
        return undef;
    }
}

sub setRename {
    my $self        = shift;
    my $newname     = shift;
    my $oldname     = shift;

    my $hash    = $defs{$newname};

    setStorePassword( $hash, $newname, getReadPassword( $hash, $oldname ) );
    setKeyValue( $hash->{TYPE} . '_' . $oldname . '_passwd', undef );   # remove old password value

    return;
}

1;


__END__

=head1 NAME

FHEM::Core::Password::Utils - FHEM extension for password handling

=head1 VERSION

This document describes FHEM::Core::Password::Utils version 0.3

=head1 CONSTRUCTOR

FHEM::Core::Password::Utils->new();

=head1 SYNOPSIS

  use FHEM::Core::Password::Utils qw(:ALL);
  our $passwd = FHEM::Core::Password::Utils->new();
  
  you can also save the password object in the instance hash
  our $hash->{helper}->{passwdobj} = FHEM::Core::Password::Utils->new();

=head1 DESCRIPTION

Store new Password
$hash->{helper}->{passwdobj}->setStorePassword('PASSWORD');

Read Password
$hash->{helper}->{passwdobj}->getReadPassword();




=head1 EXPORT

The following functions are exported by this module: 
C<setStorePassword>,C<setDeletePassword>, C<getReadPassword>, C<setRename>

=over 4

=back

=head1 OBJECTS

=head1 NOTES

=head1 BUGS AND LIMITATIONS

=head1 AUTHOR

Marko Oldenburg E<lt>fhemdevelopment AT cooltux DOT netE<gt>

=head1 LICENSE

FHEM::Core::Password::Utils is released under the same license as FHEM.

=cut
