#!/usr/bin/perl

###
#
# reconstructs binaries from pcaps. Run pcap through tcpflow first, then pipe tcpflow files to this scripts like
# cat *00023 | ../echoreconstruct.pl
#
# binaries are left in "$outputdir" (see below)
###

use Digest::SHA1 qw (sha1_hex);

my $outputdir="../malwaresamples";

# deocde lines like /bin/busybox echo -e '\x6b\x61\x6d\x69/sys' > /sys/.nippon


# no match echo -n -e '\x7F\x45\x4C\x46\x1\x1\x1\x0\x0\x0\x0\x0\x0\x0\x0\x0\x2\x0\x28\x0\x1\x0\x0\x0\x54\x80\x0\x0\x34\x0\x0\x0\xA0\x1\x0\x0\x0\x0\x0\x5\x34\x0\x20\x0\x1\x0\x28\x0\x4\x0\x3\x0\x1\x0\x0\x0\x54\x0\x0\x0\x54\x80\x0\x0\x54\x80\x0\x0\x14\x1\x0\x0\x14\x1\x0\x0\x7\x0\x0\x0\x4\x0\x0\x0\x8\x80\x48\xE0\x8\x80\x48\xE0\x8\x80\x48\xE0\x8\x80\x48\xE0\x8\x80\x48\xE0\x8\x80\x48\xE0\xFF\xD0\x4D\xE2\xFF\xD0\x4D\xE2\x2\x40\xA0\xE3\x8\x2\x84\xE0\x1\x40\xA0\xE3\x8\x12\x84\xE0\x8\x20\x88\xE0\x19\x1\x90\xEF\x8\x52\x80\xE0\x2\x40\xA0\xE3\xB2\x40' >> nyadrop

$n=0;
while(<STDIN>) {
    $line=$_;
    $line =~ s/\r//g;
    $line =~ s/\n//g;
    if ( $line =~ /echo/ ) {
    if ( $line =~ /echo -[n e-]{1,4} ['"]((\\x[a-fA-Z0-9]{1,2})+)['"] ([>]{1,2}) (\S+)/ ) {
	if ( $3 eq '>' ) {

	if ( $oldfile ne $4 ) {
	    savefile($content,$oldfile);
	} else {
	    if ( $n > 0 ) {
		savefile($content,$filename);
	    }
	}
	$n++;
	$content='';
	$filename=$4;
	}
	$content.=$1;
	$oldfile=$4;
    } else {
	print "no match ".$line."\n";
    }
    }
}
if ( $n > 0 ) {
    savefile($content,$filename);
}

sub convert {
    my $string=shift;
    $string=~ s/\\x//g;
    return pack('H*',$string);
}

sub savefile {
    my $content=shift;
    $content=convert($content);

    my $filename=shift;

    my $digest=sha1_hex($content);

    if ( -f "$outputdir/$digest.file" ) {
        print "duplicate $filename $digest\n";
	return 0;
    }
    print "saving $filename $digest\n";
    open(F,">> $outputdir/fileslist.txt" );
    print F "$filename $digest\n";
    close F;
    open(F,"> $outputdir/$digest.file") ;
    print F $content;
    close F;
}

   
