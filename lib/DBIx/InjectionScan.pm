package DBIx::InjectionScan;
use Moo;
use Module::Load 'load';
use Scalar::Util 'weaken';
use Filter::signatures;
use feature 'signatures';
no warnings 'experimental::signatures';
use Carp 'croak';

our $VERSION = '0.01';

=head1 NAME

DBIx::InjectionScan - detect when an SQL injection scan fails

=head1 SYNOPSIS

    my $dbh = DBI->connect('dbi:SQLite:dbname=:memory:', undef, undef, {
        HandleError => \&detect_injection_scan,
        #RaiseError => 1,
        PrintError => 0,
    });

    my $scan_detected = DBIx::InjectionScan->wrap(
        dbh => $dbh,
        on_detection => sub( $dbh, $statement, $file, $package, $line ) {
            warn "Possible SQL injection hole in <<$statement>> called from $location";
            # mail this information to your security team
        },
    );

=head1 DESCRIPTION

This is a detector for failed attempts of SQL injections. Alerts raised by this
detector are most likely caused by exploitable use of strings to build SQL
statements.

=head1 METHODS

=cut

has 'dbh' => (
    is       => 'ro',
    weak_ref => 1,
);

has 'detector' => (
    is       => 'rw',
);

has 'on_detection' => (
    is       => 'rw',
    default  => sub { my ( $dbh, $error, $statement, $location) = @_; 
        warn "Possible SQL injection hole in <<$statement>> called from $location ($error)";
    },
);

has 'ignore_namespaces' => (
    is       => 'rw',
    default  => sub { [] },
);

our %detectors = (
    'SQLite' => 'DBIx::InjectionScan::SQLite',
);

sub find_non_dbi_caller( $self ) {
    my $level = 1;
    my @ignore = ('DBI', ref $self, @{ $self->ignore_namespaces });
    while( $level and my @info = caller( $level++ )) {
        next if grep { $_ eq $info[0] } @ignore;
        return \@info
    };
};

sub on_error( $self, $dbh, $error, $statement ) {
    if(     my $d = $self->on_detection
        and $self->detector->detect_injection_scan( $dbh, $error, $statement )) {
        my $location = $self->find_non_dbi_caller;
        $d->( $dbh, $error, $statement, $location );
    }
}

sub dbh_install( $self, $dbh ) {
    my $previous_handler = $dbh->{HandleError};
    $dbh->{HandleError} = sub( $error, $dbh, $rv=undef ) {
        # give to previous handler
        return 1 if $previous_handler and &$previous_handler(@_);
        my $statement = $dbh->{Statement};
        $self->on_error( $dbh, $error, $statement );
    };
}

sub wrap( $class, %options ) {
    my $self = $class->new( %options );

    my $dbh_class = $self->dbh->{Driver}->{Name};
    my $detector = $detectors{ $dbh_class }
        or croak "Unknown database class '$dbh_class'"; # well, we should use a generic fallback
    load $detector;
    my $d = $detector->new();
    $self->detector( $d );

    $self->dbh_install( $self->dbh );
}

1;

__DATA__
# http://kaoticcreations.blogspot.com/2011/11/burp-suite-part-i-intro-via-sql.html
    MySQL: You have an error in your SQL syntax – SQLFiddle
    Oracle: ORA-01756: quoted string not properly terminated – SQLFiddle
    PostgreSQL: ERROR: unterminated quoted string – SQLFiddle
    SQLite: SQLite exception – SQLFiddle
    MSSQL: Invalid SQL statement or JDBC escape, terminating ”’ not found – SQLFiddle


·         unknown column
·         unknown
·         no record found
·         mysql_num_rows()
·         mysql_fetch_array()
·         Error Occurred While Processing Request
·         Server Error in '/' Application
·         Microsoft OLE DB Provider for ODBC Drivers error
·         error in your SQL syntax
·         Invalid Querystring
·         OLE DB Provider for ODBC
·         VBScript Runtime
·         ADODB.Field
·         BOF or EOF
·         ADODB.Command
·         JET Database
·         mysql_fetch_row()
·         include()
·         mysql_fetch_assoc()
·         mysql_fetch_object()
·         mysql_numrows()
·         GetArray()
·         FetchRow()
·         Input string was not in a correct format
·         Microsoft VBScript
·         A syntax error has occurred
·         ADODB.Field error
·         ASP.NET is configured to show verbose error messages
·         ASP.NET_SessionId
·         Active Server Pages error
·         An illegal character has been found in the statement
·         An unexpected token "END-OF-STATEMENT" was found
·         CLI Driver
·         Can't connect to local
·         Custom Error Message
·         DB2 Driver
·         DB2 Error
·         DB2 ODBC
·         Died at
·         Disallowed Parent Path
·         Error Diagnostic Information
·         Error Message : Error loading required libraries.
·         Error Report
·         Error converting data type varchar to numeric
·         Fatal error
·         Incorrect syntax near
·         Index of
·         Internal Server Error
·         Invalid Path Character
·         Invalid procedure call or argument
·         Invision Power Board Database Error
·         JDBC Driver
·         JDBC Error
·         JDBC MySQL
·         JDBC Oracle
·         JDBC SQL
·         Microsoft OLE DB Provider for ODBC Drivers
·         Microsoft VBScript compilation error
·         Microsoft VBScript error
·         MySQL Driver
·         MySQL Error
·         MySQL ODBC
·         ODBC DB2
·         ODBC Driver
·         ODBC Error
·         ODBC Microsoft Access
·         ODBC Oracle
·         ODBC SQL
·         ODBC SQL Server
·         OLE/DB provider returned message
·         ORA-0
·         ORA-1
·         Oracle DB2
·         Oracle Driver
·         Oracle Error
·         Oracle ODBC
·         PHP Error
·         PHP Parse error
·         PHP Warning
·         Parent Directory
·         Permission denied: 'GetObject'
·         PostgreSQL query failed: ERROR: parser: parse error
·         SQL Server Driver][SQL Server
·         SQL command not properly ended
·         SQLException
·         Supplied argument is not a valid PostgreSQL result
·         Syntax error in query expression
·         The error occurred in
·         The script whose uid is
·         Type mismatch
·         Unable to jump to row
·         Unclosed quotation mark before the character string
·         Unterminated string constant
·         Warning: Cannot modify header information - headers already sent
·         Warning: Supplied argument is not a valid File-Handle resource in
·         Warning: mysql_query()
·         Warning: pg_connect(): Unable to connect to PostgreSQL server: FATAL
·         You have an error in your SQL syntax near
·         detected an internal error [IBM][CLI Driver][DB2/6000]
·         error
·         include_path
·         invalid query
·         is not allowed to access
·         missing expression
·         mySQL error with query
·         mysql error
·         on MySQL result index
·         on line
·         server at
·         server object error
·         supplied argument is not a valid MySQL result resource
·         unexpected end of SQL command

999999 or 1=1 or 1=1
' or 1=1 or '1'='1
" or 1=1 or "1"="1
999999) or 1=1 or (1=1
') or 1=1 or ('1'='1
") or 1=1 or ("1"="1
999999)) or 1=1 or ((1=1
')) or 1=1 or (('1'='1
")) or 1=1 or (("1"="1
999999))) or 1=1 or (((1
'))) or 1=1 or ((('1'='1
"))) or 1=1 or ((("1"="1
'
"
/
/*
#
)
(
)'
('
and 1=1
and 1=2
and 1>2
and 1<=2
+and+1=1
+and+1=2
+and+1>2
+and+1<=2
/**/and/**/1=1
/**/and/**/1=2
/**/and/**/1>2
/**/and/**/1<=2

·          ORDER BY 1--
·          ORDER BY 2--
·         +ORDER+BY+1--
·         +ORDER+BY+2--
·         /**/ORDER/**/BY/**/1--
·         /**/ORDER/**/BY/**/2--

# Timing based attacks

    MySQL: select benchmark(15000000,md5(0x4e446b6e))
    PostgreSQL: select pg_sleep(15)
    SQLite: select like(‘abcdefg’,upper(hex(randomblob(150000000))))
    MSSQL,Sybase: select count(*) from sysusers as sys1,sysusers as sys2,sysusers as sys3,sysusers as sys4,sysusers as sys5,sysusers as sys6,sysusers as sys7
    Oracle: select count(*) from all_users t1,all_users t2,all_users t3,all_users t4,all_users t5
    DB2: select count(*) from sysibm.systables as t1,sysibm.systables as t2,sysibm.systables as t3
    Firebird: select count(*) from rdb$fields as t1,rdb$types as t2,rdb$collations as t3
    SAP MaxDB: select count(*) from domain.domains as t1,domain.columns as t2,domain.tables as t3
    SQL-92 Compliant DBs:  select count(*) from INFORMATION_SCHEMA.tables as sys1, INFORMATION_SCHEMA.tables as sys2, INFORMATION_SCHEMA.tables as sys3, INFORMATION_SCHEMA.tables as sys4, INFORMATION_SCHEMA.tables as sys5, INFORMATION_SCHEMA.tables as sys6


