#!perl -T
use strict;
use Config;
use Test::More;
require "../../t/loc_tools.pl";

plan skip_all => "I18N::Langinfo or POSIX unavailable" 
    if $Config{'extensions'} !~ m!\bI18N/Langinfo\b!;

my @times  = qw( MON_1 MON_2 MON_3 MON_4 MON_5 MON_6 MON_7
                 MON_8 MON_9 MON_10 MON_11 MON_12
                 DAY_1 DAY_2 DAY_3 DAY_4 DAY_5 DAY_6 DAY_7);
my @constants = qw(ABDAY_1 DAY_1 ABMON_1 RADIXCHAR AM_STR THOUSEP D_T_FMT
                   D_FMT T_FMT);
push @constants, @times;
my $debug = ($^O =~ /cygwin | mswin  /xi);
local $^D = 0x04000000|0x00100000 if $debug;
my $eval_debug = 'local $^D = 0x04000000|0x00100000;' if $debug;

my %want =
    (
        RADIXCHAR	=> ".",
        THOUSEP	=> "",
     );

# Abbreviated and full are swapped in many locales in early netbsd
if (   $Config{osname} !~ / netbsd /ix
    || $Config{osvers} !~ / ^ [1-6] \. /x)
{
    $want{ABDAY_1} = "Sun";
    $want{DAY_1}   = "Sunday";
    $want{ABMON_1} = "Jan";
    $want{MON_1}   = "January";
}

sub disp_str ($) {
    my $string = shift;

    # Displays the string unambiguously.  ASCII printables are always output
    # as-is, though perhaps separated by blanks from other characters.  If
    # entirely printable ASCII, just returns the string.  Otherwise if valid
    # UTF-8 it uses the character names for non-printable-ASCII.  Otherwise it
    # outputs hex for each non-ASCII-printable byte.

    return $string if $string =~ / ^ [[:print:]]* $/xa;

    my $result = "";
    my $prev_was_punct = 1; # Beginning is considered punct
    if (utf8::valid($string) && utf8::is_utf8($string)) {
        use charnames ();
        foreach my $char (split "", $string) {

            # Keep punctuation adjacent to other characters; otherwise
            # separate them with a blank
            if ($char =~ /[[:punct:]]/a) {
                $result .= $char;
                $prev_was_punct = 1;
            }
            elsif ($char =~ /[[:print:]]/a) {
                $result .= "  " unless $prev_was_punct;
                $result .= $char;
                $prev_was_punct = 0;
            }
            else {
                $result .= "  " unless $prev_was_punct;
                my $name = charnames::viacode(ord $char);
                $result .= (defined $name) ? $name : ':unknown:';
                $prev_was_punct = 0;
            }
        }
    }
    else {
        use bytes;
        foreach my $char (split "", $string) {
            if ($char =~ /[[:punct:]]/a) {
                $result .= $char;
                $prev_was_punct = 1;
            }
            elsif ($char =~ /[[:print:]]/a) {
                $result .= " " unless $prev_was_punct;
                $result .= $char;
                $prev_was_punct = 0;
            }
            else {
                $result .= " " unless $prev_was_punct;
                $result .= sprintf("%02X", ord $char);
                $prev_was_punct = 0;
            }
        }
    }

    return $result;
}

my @want = sort keys %want;

#plan tests => 1 + 3 * @constants + keys(@want) + 1 + 2;

use_ok('I18N::Langinfo', 'langinfo', @constants, 'CRNCYSTR');

use POSIX;
setlocale(LC_ALL, "C");

for my $constant (@constants) {
    SKIP: {
        my $string = eval { langinfo(eval "$constant()") };
        is( $@, '', "calling langinfo() with $constant" );
        skip "returned string was empty, skipping next two tests", 2 unless $string;
        ok( defined $string, "checking if the returned string is defined" );
        cmp_ok( length($string), '>=', 1, "checking if the returned string has a positive length" );
    }
}

for my $i (1..@want) {
    my $try = $want[$i-1];
    eval { I18N::Langinfo->import($try) };
    SKIP: {
        skip "$try not defined", 1, if $@;
        no strict 'refs';
        is (langinfo(&$try), $want{$try}, "$try => '$want{$try}'");
    }
}

my $comma_locale;
for (find_locales( [ 'LC_NUMERIC' ] )) {
    use POSIX;
    use locale;
    setlocale(LC_NUMERIC, $_) or next;
    my $in = 4.2; # avoid any constant folding bugs
    my $s = sprintf("%g", $in);
    if ($s eq "4,2")  {
        $comma_locale = $_;
        last;
    }
}

SKIP: {
    skip "Couldn't find a locale with a comma decimal pt", 1
                                                        unless $comma_locale;

    no strict 'refs';
    is (langinfo(&RADIXCHAR), ",",
        "Returns ',' for decimal pt for locale '$comma_locale'");
}

SKIP: {

    my $found_time = 0;
    my $found_monetary = 0;
    my @locales = find_locales( [ 'LC_TIME', 'LC_CTYPE', 'LC_MONETARY' ]);
    my @utf8_locales = find_utf8_ctype_locales(\@locales);

    foreach my $utf8_locale (@utf8_locales) {

        if (! $found_time) {
            print STDERR __FILE__, ": ", __LINE__, ": calling setlocale(LC_TIME, $utf8_locale)\n" if $debug;
            my $set_ret = setlocale(&LC_TIME, $utf8_locale);
            print STDERR __FILE__, ": ", __LINE__, ": setlocale returned '$set_ret'\n" if $debug;
            foreach my $time_item (@times) {
                print STDERR __FILE__, ": ", __LINE__, ": ", setlocale(&LC_TIME), "\n" if $debug;
                my $eval_string = "$eval_debug langinfo(&$time_item)";
                print STDERR __FILE__, ": ", __LINE__, ": ", setlocale(&LC_TIME), "\n" if $debug;
                my $time_name = eval $eval_string;
                if ($@) {
                    fail("'$eval_string' failed: $@");
                    last SKIP;
                }
                if (! defined $time_name) {
                    fail("'$eval_string' returned undef");
                    last SKIP;
                }
                if ($time_name eq "") {
                    fail("'$eval_string' returned an empty name");
                    last SKIP;
                }

                if ($time_name =~ /\P{ASCII}/) {
                    ok(utf8::is_utf8($time_name), "The name for '$time_item' in $utf8_locale is a UTF8 string.  Got:\n" . disp_str($time_name));
                    #$found_time = 1;
                    last;
                }
            }
        }

        if (! $found_monetary) {
            print STDERR __FILE__, ": ", __LINE__, ": calling setlocale(LC_MONETARY, $utf8_locale)\n" if $debug;
            setlocale(&LC_MONETARY, $utf8_locale);
            print STDERR __FILE__, ": ", __LINE__, ": setlocale returned\n" if $debug;
            my $eval_string = "$eval_debug langinfo(&CRNCYSTR)";
            my $symbol = eval $eval_string;
            if ($@) {
                fail("'$eval_string' failed: $@");
                last SKIP;
            }
            if (! defined $symbol) {
                fail("'$eval_string' returned undef");
                last SKIP;
            }
            if ($symbol =~ /\P{ASCII}/) {
                ok(utf8::is_utf8($symbol), "The name for 'CRNCYSTR' in $utf8_locale is a UTF8 string.  Got:\n" . disp_str($symbol));
                #$found_monetary = 1;
            }
        }

        last if $found_monetary && $found_time;
    }

    if ($found_time + $found_monetary < 2) {
        my $message = "";
        $message .= "time name" unless $found_time;
        if (! $found_monetary) {
            $message .= " nor" if $message;
            "monetary name";
        }
        skip("Couldn't find a locale with a non-ascii $message", 2 - $found_time - $found_monetary);
    }
}

done_testing();
