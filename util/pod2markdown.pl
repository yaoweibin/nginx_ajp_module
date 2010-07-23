#!/usr/bin/perl 
#===============================================================================
#
#         FILE:  pod2markdown.pl
#
#        USAGE:  ./pod2markdown.pl  
#
#  DESCRIPTION:  pod2markdown
#
#      OPTIONS:  ---
# REQUIREMENTS:  ---
#         BUGS:  ---
#        NOTES:  ---
#       AUTHOR:  YOUR NAME (), 
#      COMPANY:  
#      VERSION:  1.0
#      CREATED:  07/23/2010 01:22:27 PM
#     REVISION:  ---
#===============================================================================

use strict;
use warnings;
use Pod::Parser; 
use Pod::Markdown;

my $parser = Pod::Markdown->new;

$parser->parse_from_filehandle(\*STDIN);

print $parser->as_markdown;

