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
#   substr3          ferm's @substr body (inline at ferm:1570); the
#                    record carries three \x01-separated fields, and
#                    Perl numifies the offset/length strings itself
#   option_token     import-ferm's option-token classifier (inline at
#                    import-ferm:578, copied verbatim below)
#   read_previous    ferm's save-dump reader (source: reference/src/ferm);
#                    the reply is a canonical table/chain layout
#
# Protocol: stdin carries NUL-terminated records (no NUL in payload).
#   escape_*, substr3 -> the resulting string, NUL-terminated
#   the rest  -> token count and the tokens, all joined with \x01,
#                NUL-terminated (the count disambiguates an empty list
#                from a single empty token, which import_tokenize can
#                produce for `""`)
#
# No `use strict`: the extracted subs reference the oracle's package
# global %option (declared there via `use vars`), which here is plain
# %main::option.
use warnings;
# 'once': %main::option is assigned here but read only inside the
# eval'ed sub, which the "used only once" heuristic cannot see.
# numeric/uninitialized/substr: the oracle runs without `use warnings`,
# so junk @substr parameters must numify (and go out of range) silently
# here too.
no warnings qw(once numeric uninitialized substr);

my %extracted_subs = (
    tokenize        => ['tokenize_string'],
    escape_fast     => ['shell_escape'],
    escape_slow     => ['shell_escape'],
    import_tokenize => ['tokenize'],
    backtick_split  => [],
    substr3         => [],
    option_token    => [],
    read_previous   => ['read_previous'],
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
    # the prototype varies: ($) for the lexers, ($$) for read_previous
    my ($sub) = $code =~ /^(sub \Q$name\E\([\$]*\) \{.*?^\})/ms
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
    } elsif ($function eq 'substr3') {
        my @params = split /\x01/, $record, -1;
        # verbatim from reference/src/ferm:1570; ferm later interpolates
        # the result into strings, where an out-of-range undef reads as ''
        my $result = substr($params[0],$params[1],$params[2]);
        print $result // '', "\0";
    } elsif ($function eq 'option_token') {
        # verbatim from reference/src/import-ferm:578
        local $_ = $record;
        if (/^-(\w)$/ || /^--(\S+)$/) {
            reply_tokens($1);
        } else {
            reply_tokens();
        }
    } elsif ($function eq 'read_previous') {
        local $/ = "\n";  # the protocol's "\0" must not leak into <$fh>
        open my $dump, '<', \$record or die "in-memory open: $!\n";
        my $domain_info = {};
        read_previous($dump, $domain_info);
        close $dump;
        my @layout;
        foreach my $table (sort keys %{$domain_info->{tables} || {}}) {
            my $table_info = $domain_info->{tables}{$table};
            push @layout, "*$table";
            push @layout, '+' if $table_info->{has_builtin};
            push @layout, sort grep { $table_info->{chains}{$_}{builtin} }
              keys %{$table_info->{chains} || {}};
        }
        reply_tokens(@layout);
    } else {
        print shell_escape($record), "\0";
    }
}
