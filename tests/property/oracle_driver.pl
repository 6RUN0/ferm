# Differential-fuzzing driver: extract pure subs verbatim from the
# frozen Perl oracle and serve them over a NUL-delimited stdin/stdout
# protocol, so each Hypothesis example costs one pipe round-trip
# instead of one perl(1) start-up.
#
# Usage: perl oracle_driver.pl <path/to/source> <function>
# where <function> is one of:
#   tokenize         ferm's tokenize_string (source: reference/src/ferm)
#   escape_fast      ferm's shell_escape with $option{fast} (ditto)
#   escape_slow      ferm's shell_escape without it (ditto)
#   import_tokenize  import-ferm's tokenize (source: reference/src/import-ferm)
#   backtick_split   ferm's backtick-output comment-strip + split
#                    (inline code at ferm:1470/:1473, copied verbatim
#                    below -- it has no sub of its own to extract)
#
# Protocol: stdin carries NUL-terminated records (no NUL in payload).
#   escape_*  -> the escaped token, NUL-terminated
#   the rest  -> token count and the tokens, all joined with \x01,
#                NUL-terminated (the count disambiguates an empty list
#                from a single empty token, which import_tokenize can
#                produce for `""`)
#
# No `use strict`: the extracted subs reference the oracle's package
# global %option (declared there via `use vars`), which here is plain
# %main::option.
use warnings;
# %main::option is assigned here but read only inside the eval'ed sub,
# which the "used only once" heuristic cannot see.
no warnings 'once';

my %extracted_subs = (
    tokenize        => ['tokenize_string'],
    escape_fast     => ['shell_escape'],
    escape_slow     => ['shell_escape'],
    import_tokenize => ['tokenize'],
    backtick_split  => [],
);

my ($source, $function) = @ARGV;
die "usage: oracle_driver.pl SOURCE FUNCTION\n"
  unless defined $function;
die "unknown function: $function\n"
  unless exists $extracted_subs{$function};

open my $fh, '<', $source or die "open $source: $!\n";
my $code = do { local $/; <$fh> };
close $fh;

foreach my $name (@{$extracted_subs{$function}}) {
    my ($sub) = $code =~ /^(sub \Q$name\E\(\$\) \{.*?^\})/ms
      or die "cannot extract sub $name from $source\n";
    eval $sub;
    die $@ if $@;
}

%main::option = (fast => $function eq 'escape_fast' ? 1 : 0);

sub reply_tokens {
    print join("\x01", scalar(@_), @_), "\0";
}

$| = 1;
local $/ = "\0";
while (defined(my $record = <STDIN>)) {
    chomp $record;
    if ($function eq 'tokenize') {
        reply_tokens(@{tokenize_string($record)});
    } elsif ($function eq 'import_tokenize') {
        reply_tokens(tokenize($record));
    } elsif ($function eq 'backtick_split') {
        # verbatim from reference/src/ferm:1470 and :1473
        $record =~ s/#.*//mg;
        reply_tokens(grep { length } split /\s+/s, $record);
    } else {
        print shell_escape($record), "\0";
    }
}
