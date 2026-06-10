# Differential-fuzzing driver: extract pure subs verbatim from the
# frozen Perl oracle and serve them over a NUL-delimited stdin/stdout
# protocol, so each Hypothesis example costs one pipe round-trip
# instead of one perl(1) start-up.
#
# Usage: perl oracle_driver.pl <path/to/ferm> <tokenize|escape_fast|escape_slow>
#
# Protocol: stdin carries NUL-terminated records (no NUL in payload).
#   tokenize     -> tokens joined with \x01, NUL-terminated
#   escape_*     -> the escaped token, NUL-terminated
#
# No `use strict`: the extracted subs reference the oracle's package
# global %option (declared there via `use vars`), which here is plain
# %main::option.
use warnings;
# %main::option is assigned here but read only inside the eval'ed sub,
# which the "used only once" heuristic cannot see.
no warnings 'once';

my ($source, $function) = @ARGV;
die "usage: oracle_driver.pl SOURCE FUNCTION\n"
  unless defined $function;
my %known = map { $_ => 1 } qw(tokenize escape_fast escape_slow);
die "unknown function: $function\n"
  unless $known{$function};

open my $fh, '<', $source or die "open $source: $!\n";
my $code = do { local $/; <$fh> };
close $fh;

foreach my $name (qw(tokenize_string shell_escape)) {
    my ($sub) = $code =~ /^(sub \Q$name\E\(\$\) \{.*?^\})/ms
      or die "cannot extract sub $name from $source\n";
    eval $sub;
    die $@ if $@;
}

%main::option = (fast => $function eq 'escape_fast' ? 1 : 0);

$| = 1;
local $/ = "\0";
while (defined(my $record = <STDIN>)) {
    chomp $record;
    if ($function eq 'tokenize') {
        print join("\x01", @{tokenize_string($record)}), "\0";
    } else {
        print shell_escape($record), "\0";
    }
}
