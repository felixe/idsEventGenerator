#!/usr/bin/perl -w
use String::Random qw/random_regex/;

$num_args = $#ARGV + 1;
if ($num_args != 1) {
    print "\nregexStringGenerator: no regex given\n";
    exit;
}
$regex=$ARGV[0];


print random_regex($regex), "\n";
