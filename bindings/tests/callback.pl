#!/usr/bin/perl -w
#

use strict;

push @INC,".";
push @INC,"./perl";
push @INC,"./.libs";

eval  { require RequiemEasy; };
die "Could not load RequiemEasy ($@).\nTry 'cd ./.libs && ln -s librequiem_perl.so RequiemEasy.so'" if $@;

sub PrintUID
{
	print "UID is $<\n";
}

RequiemEasy::set_perlmethod(\&PrintUID);

RequiemEasy::test_fct();
