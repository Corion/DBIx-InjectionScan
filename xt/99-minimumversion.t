#!perl -w
use strict;
use Test::More;

eval {
  #require Test::MinimumVersion::Fast;
  require Test::MinimumVersion;
  Test::MinimumVersion->import;
};

my @files;

if ($@) {
  plan skip_all => "Test::MinimumVersion required for testing minimum Perl version";
}
else {
  #all_minimum_version_from_metajson_ok();
  # our use of Filter::signatures + feature throws it off
  all_minimum_version_ok('5.010');
}
