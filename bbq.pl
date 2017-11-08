#!perl

# partially working: uricontent (some weird urls and hex chars not working)
# experimental: distance, byte_test, byte_jump, offset
# not working: flowbits, pcre

use strict;
use warnings;
use Config::Simple;
use Tk;
use Tk::HList;
use Tk::FileEntry;
use Tk::StatusBar;
use Tk::ItemStyle;
use Tk::Checkbox;
use Tk::HdrResizeButton;
use Tk::JComboBox;
use Net::RawIP;
use NetAddr::IP;
use Net::Pcap;
use LWP::Simple;
use MIME::Base64 qw( encode_base64 decode_base64 );
use HTTP::Daemon;
use HTTP::Client;
use threads;

use URI::Normalize qw( normalize_uri );

use IO::Socket::INET;
use Socket;
use Sys::Hostname qw(hostname);
use Net::PcapUtils;
use NetPacket::Ethernet qw(:strip);
use NetPacket::IP qw(:strip);
use NetPacket::TCP;

use constant COMM_PORT => 7777;
my $local_ip = "169.254.222.155"; # TODO: GET LOCAL IP FROM SOCKET

my $comm = $ARGV[0];

my %config = (
  "TARGET_IP"      , "",
  "HOME_NET"       , "",
  "EXTERNAL_NET"   , "",
  "DNS_SERVERS"    , "",
  "SMTP_SERVERS"   , "",
  "HTTP_SERVERS"   , "",
  "SQL_SERVERS"    , "",
  "TELNET_SERVERS" , "",
  "SSH_SERVERS"    , "",
  "FTP_SERVERS"    , "",
  "SIP_SERVERS"    , "",
  "HTTP_PORTS"     , "",
  "SHELLCODE_PORTS", "",
  "ORACLE_PORTS"   , "",
  "SSH_PORTS"      , "",
  "FTP_PORTS"      , "",
  "SIP_PORTS"      , "",
  "FILE_DATA_PORTS", "",
  "GTP_PORTS"      , "",
  "AIM_SERVERS"    , ""
);

my %additional_data = ();

# fill variables with config data
read_config();

# run this script with argument "-r" to initiate receiver mode
# else it runs in sender mode
if ($comm eq "-r")
{
  print "Running in receiver mode.\n";
  # auto-flush on socket
  $| = 1;

  # creating a listening socket
  my $socket = new IO::Socket::INET (
      LocalHost => $config{"TARGET_IP"},
      LocalPort => COMM_PORT,
      Proto => 'tcp',
      Listen => 5,
      Reuse => 1
  );
  die "cannot create socket $!\n" unless $socket;
  print "server waiting for client connection at ".$config{"TARGET_IP"}.":".COMM_PORT."\n";
  my $fi = " ";

  my $socket2;

  while(1)
  {
      # wait for new client connection
      my $client_socket = $socket->accept();

      # get information about the client
      my $client_address = $client_socket->peerhost();
      my $client_port = $client_socket->peerport();
      print "connection from $client_address:$client_port\n";

      my $request = "";
      $client_socket->recv($request, 1024);

      if ($request =~ /^open:/)
      {
        my $req =  (split(/:/, $request))[1];
        my $port = (split(/;/, $req))[0];
        $socket2->close if ($socket2);
        undef $socket2;
        if ($request =~ /is_http/)
        {
          $socket2 = HTTP::Daemon->new(LocalAddr => $ARGV[0],
                          LocalPort => $port,
                          Listen => 20) || die;
        }
        else
        {
          $socket2 = new IO::Socket::INET (
              LocalHost => $config{"TARGET_IP"},
              LocalPort => $port,
              Proto => 'tcp',
              Listen => 5,
              Reuse => 1
          );
          die "cannot create socket $!\n" unless $socket;
        }

        print "opened socket on port $port\n";
      }
      elsif ($request =~ /^send_raw:/)
      {
        my @data = split(/,/,(split(/:/, $request))[1]);
        my $src_ip   = $data[0];
        my $src_port = $data[1];
        my $dst_ip   = $data[2];
        my $dst_port = $data[3];
        my $payload  = decode_base64($data[4]);

        my $n = Net::RawIP->new({
            ip  => {
                    saddr => $src_ip,
                    daddr => $dst_ip,
                   },
            tcp => {
                    source => $src_port,
                    dest   => $dst_port,
                    data   => $payload
                   },
        });
        $n->send;
      }
      elsif ($request =~ /^send:/)
      {
        my @data = split(/,/,(split(/:/, $request))[1]);
        my $src_port = $data[0];
        my $payload = decode_base64($data[1]);

        if ($src_port ne COMM_PORT)
        {
          $socket2->close if ($socket2);

          $socket2 = new IO::Socket::INET (
              LocalHost => $config{"TARGET_IP"},
              LocalPort => $src_port,
              Proto => 'tcp',
              Listen => 5,
              Reuse => 1
          );
          die "cannot create socket $!\n" unless $socket;
          print "opened socket on port $src_port\n";
        }

        $client_socket->send("OK");
        my $sock = $socket;
           $sock = $socket2 if ($socket2);
        my $client_socket2 = $sock->accept();
        my $client_address = $client_socket2->peerhost();
        my $client_port = $client_socket2->peerport();
        print "connection from $client_address:$client_port\n";
        $client_socket2->send($payload);
        print "sent payload \"$payload\" back.\n";
        $client_socket2->close();
        if ($src_port ne COMM_PORT && $socket2)
        {
          close $socket2;
          undef $socket2;
        }
      }
  }
  $socket2->close if($socket2);
  $socket->close();
  print "exit.";
  exit(0);
}
else ################################################################# SENDER MODE
{
  if ($comm eq "-s")
  {
    print "Running in sender mode.\n";
  }
  else
  {
    print "Defaulting to sender mode.\n";
  }

  my $pcap;
  my $item_counter = 0;
  my %flowbits_set = ();

  # initialize main window
  my $mw = Tk::MainWindow->new;
     $mw->bind('all' => '<Key-Escape>' => sub {exit;});
     $mw->title('BBQ');
     $mw->geometry(($mw->maxsize())[0] .'x'.($mw->maxsize())[1]);

   my $main_icon = $mw->Photo( -file => 'icon.gif', -format => 'gif' );
   $mw->Icon( -image => $main_icon );

  # create the window's menubar
  my $menuitems = [
    [Cascade => "File", -menuitems =>
        [
            [Button => "Open", -command => \&parse_ruleset]
        ],
    ],
    [Cascade => "Actions", -menuitems =>
        [
            [Button => "Fire Selected", -command => \&fire_selected],
            [Button => "Fire All", -command => \&fire_all],
            [Button => "Flood", -command => \&flood],
            [Button => "Benchmark", -command => \&benchmark],
            [Button => "Benchmark Selected", -command => \&benchmark_selected],
            [Button => "Fire Manual Rule", -command => \&fire_manual],
        ],
    ],
    [Button => "Settings", -command => \&open_settings]
  ];

  my $menu = $mw->Menu(-menuitems => $menuitems);
  $mw->configure(-menu => $menu);
  $menu->entryconfigure(2, -state => 'disabled'); # disable the actions until a ruleset has been loaded
  my $e = $menu->Entry(
  	-width => 40,
  	-relief => 'sunken',
  	-bd => 2,
  );

  my $hlist = $mw->Scrolled("HList",
    -header => 1,
    -columns => 9,
    -scrollbars => 'osoe',
    -width => 500,
    -command => \&fire_selected,
    -selectmode => 'extended',
    -selectbackground => 'MediumSeaGreen',
    -highlightthickness => 0
  )->pack(-expand => 1, -fill => 'both');

  my $headerstyle   = $hlist->ItemStyle('window', -padx => 0, -pady => 0);

  my $h0 = $hlist->HdrResizeButton(-text => 'ID', relief => 'flat', -pady => 0, -command => [\&sort_hlist, 0], -column => 0);
  $hlist->header('create', 0, -itemtype => 'window', -widget => $h0, -style=>$headerstyle);

  my $h1 = $hlist->HdrResizeButton(-text => 'Action', relief => 'flat', -pady => 0, -command => [\&sort_hlist, 1], -column => 1);
  $hlist->header('create', 1, -itemtype => 'window', -widget => $h1, -style=>$headerstyle);

  my $h2 = $hlist->HdrResizeButton(-text => 'Protocol', relief => 'flat', -pady => 0, -command => [\&sort_hlist, 2], -column => 2);
  $hlist->header('create', 2, -itemtype => 'window', -widget => $h2, -style=>$headerstyle);

  my $h3 = $hlist->HdrResizeButton(-text => 'Source IP', relief => 'flat', -pady => 0, -command => [\&sort_hlist, 3], -column => 3);
  $hlist->header('create', 3, -itemtype => 'window', -widget => $h3, -style=>$headerstyle);

  my $h4 = $hlist->HdrResizeButton(-text => 'Source Port', relief => 'flat', -pady => 0, -command => [\&sort_hlist, 4], -column => 4);
  $hlist->header('create', 4, -itemtype => 'window', -widget => $h4, -style=>$headerstyle);

  my $h5 = $hlist->HdrResizeButton(-text => 'Direction', relief => 'flat', -pady => 0, -command => [\&sort_hlist, 5], -column => 5);
  $hlist->header('create', 5, -itemtype => 'window', -widget => $h5, -style=>$headerstyle);

  my $h6 = $hlist->HdrResizeButton(-text => 'Destination IP', relief => 'flat', -pady => 0, -command => [\&sort_hlist, 6], -column => 6);
  $hlist->header('create', 6, -itemtype => 'window', -widget => $h6, -style=>$headerstyle);

  my $h7 = $hlist->HdrResizeButton(-text => 'Destination Port', relief => 'flat', -pady => 0, -command => [\&sort_hlist, 7], -column => 7);
  $hlist->header('create', 7, -itemtype => 'window', -widget => $h7, -style=>$headerstyle);

  my $h8 = $hlist->HdrResizeButton(-text => 'Message', relief => 'flat', -pady => 0, -command => [\&sort_hlist, 8], -column => 8);
  $hlist->header('create', 8, -itemtype => 'window', -widget => $h8, -style=>$headerstyle);

  my $sb = $mw->StatusBar();
  my $sb_label = $sb->addLabel(
      -text           => 'Please select a ruleset.',
      -width          => '30',
      -anchor         => 'center',
  );

  $mw->MainLoop;
  exit(0);

  sub sort_hlist()
  {
    my $col = shift;

    my @entries = $hlist->info('children');
    my @items = ();

    foreach my $entry(@entries){
             push @items, [ $hlist->itemCget($entry,0,'text'),
                            $hlist->itemCget($entry,1,'text'),
                            $hlist->itemCget($entry,2,'text'),
                            $hlist->itemCget($entry,3,'text'),
                            $hlist->itemCget($entry,4,'text'),
                            $hlist->itemCget($entry,5,'text'),
                            $hlist->itemCget($entry,6,'text'),
                            $hlist->itemCget($entry,7,'text'),
                            $hlist->itemCget($entry,8,'text')
                          ];
    }
    my @sorted = ();

    if ($col == 0)
    {
      @sorted = sort{ $a->[0] <=> $b->[0] } @items;
    }
    else
    {
      @sorted = sort{ $a->[$col] cmp $b->[$col] || $a->[0] <=> $b->[0] } @items;
    }

    my $entry = 0;
    foreach my $arr (@sorted){
      $hlist->itemConfigure( $entry, 0, 'text' => $arr->[0] );
      $hlist->itemConfigure( $entry, 1, 'text' => $arr->[1] );
      $hlist->itemConfigure( $entry, 2, 'text' => $arr->[2] );
      $hlist->itemConfigure( $entry, 3, 'text' => $arr->[3] );
      $hlist->itemConfigure( $entry, 4, 'text' => $arr->[4] );
      $hlist->itemConfigure( $entry, 5, 'text' => $arr->[5] );
      $hlist->itemConfigure( $entry, 6, 'text' => $arr->[6] );
      $hlist->itemConfigure( $entry, 7, 'text' => $arr->[7] );
      $hlist->itemConfigure( $entry, 8, 'text' => $arr->[8] );
      $entry++;
    }

    $mw->update;
  }

  sub read_config()
  {
    my %config_file = ();
    my $cfg = Config::Simple->import_from('bbq.conf', \%config_file);

    $config{"TARGET_IP"}       = $config_file{"TARGET_IP"};
    $config{"INTERFACE"}       = $config_file{"INTERFACE"};
    $config{"HOME_NET"}        = $config_file{"HOME_NET"};
    $config{"EXTERNAL_NET"}    = $config_file{"EXTERNAL_NET"};
    $config{"DNS_SERVERS"}     = $config_file{"DNS_SERVERS"};
    $config{"SMTP_SERVERS"}    = $config_file{"SMTP_SERVERS"};
    $config{"HTTP_SERVERS"}    = $config_file{"HTTP_SERVERS"};
    $config{"SQL_SERVERS"}     = $config_file{"SQL_SERVERS"};
    $config{"TELNET_SERVERS"}  = $config_file{"TELNET_SERVERS"};
    $config{"SSH_SERVERS"}     = $config_file{"SSH_SERVERS"};
    $config{"FTP_SERVERS"}     = $config_file{"FTP_SERVERS"};
    $config{"SIP_SERVERS"}     = $config_file{"SIP_SERVERS"};
    $config{"HTTP_PORTS"}      = $config_file{"HTTP_PORTS"};
    $config{"SHELLCODE_PORTS"} = $config_file{"SHELLCODE_PORTS"};
    $config{"ORACLE_PORTS"}    = $config_file{"ORACLE_PORTS"};
    $config{"SSH_PORTS"}       = $config_file{"SSH_PORTS"};
    $config{"FTP_PORTS"}       = $config_file{"FTP_PORTS"};
    $config{"SIP_PORTS"}       = $config_file{"SIP_PORTS"};
    $config{"FILE_DATA_PORTS"} = $config_file{"FILE_DATA_PORTS"};
    $config{"GTP_PORTS"}       = $config_file{"GTP_PORTS"};
    $config{"AIM_SERVERS"}     = $config_file{"AIM_SERVERS"};
    print "Config loaded.\n";
  }

  sub write_config()
  {
    my $cfg = Config::Simple->import_from('bbq.conf');
       $cfg->param('TARGET_IP',       $config{"TARGET_IP"});
       $cfg->param('INTERFACE',       $config{"INTERFACE"});
       $cfg->param('HOME_NET',        $config{"HOME_NET"});
       $cfg->param('EXTERNAL_NET',    $config{"EXTERNAL_NET"});
       $cfg->param('DNS_SERVERS',     $config{"DNS_SERVERS"});
       $cfg->param('SMTP_SERVERS',    $config{"SMTP_SERVERS"});
       $cfg->param('HTTP_SERVERS',    $config{"HTTP_SERVERS"});
       $cfg->param('SQL_SERVERS',     $config{"SQL_SERVERS"});
       $cfg->param('TELNET_SERVERS',  $config{"TELNET_SERVERS"});
       $cfg->param('SSH_SERVERS',     $config{"SSH_SERVERS"});
       $cfg->param('FTP_SERVERS',     $config{"FTP_SERVERS"});
       $cfg->param('SIP_SERVERS',     $config{"SIP_SERVERS"});
       $cfg->param('HTTP_PORTS',      $config{"HTTP_PORTS"});
       $cfg->param('SHELLCODE_PORTS', $config{"SHELLCODE_PORTS"});
       $cfg->param('ORACLE_PORTS',    $config{"ORACLE_PORTS"});
       $cfg->param('SSH_PORTS',       $config{"SSH_PORTS"});
       $cfg->param('FTP_PORTS',       $config{"FTP_PORTS"});
       $cfg->param('FILE_DATA_PORTS', $config{"FILE_DATA_PORTS"});
       $cfg->param('GTP_PORTS',       $config{"GTP_PORTS"});
       $cfg->param('AIM_SERVERS',     $config{"AIM_SERVERS"});
       $cfg->save();
  }

  sub str2time {
    my ($str) = @_;
    $str =~ s/(\.[0-9]+)?\z//;
    my $fraction = $1 || 0;
    return Time::Piece->strptime($str, '%m/%d-%H:%M:%S')->epoch + $fraction;
  }

  sub parse_ruleset()
  {
    my $filename =  $mw->getOpenFile();
    $hlist->delete("all");
    open(my $fh, '<:encoding(UTF-8)', $filename)
      or die "Could not open file '$filename' $!";

    $item_counter = 0;
    %additional_data = ();
    while (my $row = <$fh>) {
      my @all_elements = split / /, $row;
         @all_elements = grep { $_ ne '' } @all_elements;
      if ($all_elements[0] eq '#' || substr($row, 0, 1) eq '#' || scalar(@all_elements) < 2){ next; } # skip comments
      my $dontadd = 0;
      my $dst = $all_elements[5];
      my $src = $all_elements[2];

      my $neg = 1 if ($dst =~ /!/);
      if ($dst =~ /\$/)
      {
        $dst =~ s/\$//g;
        $dst =~ s/!//g;
        if (exists $config{"$dst"})
        {
          $dst = $config{"$dst"};
        }
        else
        {
          print "[ERROR] Can't resolve \"$dst\"\n";
        }
      }
      if ($src =~ /\$/)
      {
        $src =~ s/\$//g;
        $src =~ s/!//g;
        if (exists $config{"$src"})
        {
          $src = $config{"$src"};
        }
        else
        {
          print "[ERROR] Can't resolve \"$dst\"\n";
        }
      }

      if ($dst eq "any" && $neg)
      {
        # cant fulfill target "not any"
        $dontadd = 1;
      }
      elsif (ref($dst) eq 'ARRAY')
      {
        $dontadd = 1;
        foreach my $item (@{$dst})
        {
          $dontadd = 0 if ($item eq $config{"TARGET_IP"});
        }
      }
      elsif ($dst ne "any")
      {
        $dst = (split(/\//, $dst))[0] if ($dst =~ /\//);
        $dst =~ s/\[//g;

        if ($dst ne $config{"TARGET_IP"})
        {
            # we don't just skip here, because data like flowbits should still be stored in the background
            $dontadd = 1;
        }
      }

      if ($src eq "any" && $neg)
      {
        # cant fulfill source "not any"
        $dontadd = 1;
      }
      elsif (ref($src) eq 'ARRAY')
      {
        $dontadd = 1;
        foreach my $item (@{$src})
        {
          $dontadd = 0 if ($item eq $local_ip);
        }
      }
      elsif ($src ne "any")
      {
        $src = (split(/\//, $dst))[0] if ($dst =~ /\//);
        $src =~ s/\[//g;

        if ($src ne $local_ip)
        {
            # we don't just skip here, because data like flowbits should still be stored in the background
            $dontadd = 1;
        }
      }

      my ($options) = $row =~ /\((.*?)\)/; # extract options part in brackets
    #  $options =~ s/\"//g;                 # remove " from string
      my @elements = split /;/, $options;

      my %optionlist = ();
      my $counter = 0;
      foreach my $el (@elements)
      {
        my @expr = split /:/, $el;
        $expr[0] =~ s/^\s+//;
        $optionlist{$counter .":". $expr[0]} = $expr[1];
        $counter++;
      }

      foreach my $k (keys %optionlist)
      {
        my $d = $optionlist{$k};
        if ($k =~ /flowbits/)
        {
          # e.g. flowbits:set,backdoor.asylum.connect
          if ($d =~ /^set/)
          {
            my @spl = split(/,/, $d);
            $flowbits_set{$spl[1]} = \@all_elements;
          }
          # if the rule triggers no alert, we don't need to let the user fire it
          # they may be used to set a flowbit though
          if ($d =~ /noalert/)
          {
            $dontadd = 1;
          }
        }
        # don't show the alert if it has unsupported keywords
        if ($k =~ /pcre/ || $k =~/flowbits/ || $k =~ /sameip/)
        {
          $dontadd = 1;
        }
      }

      if (!$dontadd)
      {
        $hlist->add($item_counter);
        $hlist->itemCreate($item_counter, 0, -text => $item_counter);
        $hlist->itemCreate($item_counter, 1, -text => $all_elements[0]);
        $hlist->itemCreate($item_counter, 2, -text => $all_elements[1]);
        $hlist->itemCreate($item_counter, 3, -text => $all_elements[2]);
        $hlist->itemCreate($item_counter, 4, -text => $all_elements[3]);
        $hlist->itemCreate($item_counter, 5, -text => $all_elements[4]);
        $hlist->itemCreate($item_counter, 6, -text => $all_elements[5]);
        $hlist->itemCreate($item_counter, 7, -text => $all_elements[6]);
        foreach my $k (keys %optionlist)
        {
          if ($k =~ /:msg/)
          {
            $optionlist{$k} =~ s/\"//g; # remove " from string
            $hlist->itemCreate($item_counter, 8, -text => $optionlist{$k});
            last;
          }
        }
      }
      $additional_data{$item_counter} = \%optionlist;

      $item_counter++ if (!$dontadd);
    }

    # ruleset has been loaded, so we update the status text and enable the actions menu
    $sb_label->configure(-text => "");
    $menu->entryconfigure(2, -state => 'normal');
  }

  sub fire_selected()
  {
    my @selectedindices = $hlist->info('selection');

    foreach my $idx (@selectedindices)
    {
      my @row;
      foreach my $col (0 .. $hlist->cget(-columns) -1)
      {
        push @row, $hlist->itemCget($idx, $col, '-text');
      }
      fire(\@row);
    }

    if (scalar(@selectedindices) == 0)
    {
      $mw->messageBox(-icon => 'error', -message => 'No rule selected!', -title => 'Error', -type => 'Ok');
    }
  }

  sub benchmark_selected()
  {
    my $endtime = time() + 60;
    while(time() <= $endtime)
    {
      sleep 1;
      fire_selected();
    }
  }

  # Fire all rules sequentially
  sub fire_all()
  {
    foreach my $row (0 .. $item_counter - 1)
    {
      my @r;
      foreach my $col (0 .. $hlist->cget(-columns) -1)
      {
        push @r, $hlist->itemCget($row, $col, '-text');
      }
      sleep(0.9); # dont DOS the server
      fire(\@r);
    }
  }

  sub flood()
  {
    # we udp flood first and then mix some random attacks in

    my $PRE_FLOOD_TIME  =  5; # run udp flood for this amount of seconds until starting to send actual "malware" packets
    my $PACKET_INTERVAL =  1; # time interval between "malware" packets
    my $NUM_ATTACKS     = 25; # number of "malware" packets

    my $ip = $config{"TARGET_IP"};
    my $port = COMM_PORT;
    my $size = 512;

    my $iaddr = inet_aton("$ip") or die "Cannot resolve hostname $ip\n";
    my $endtime = time() + $PRE_FLOOD_TIME;


    my $thr = threads->create( sub {
          socket("flood", PF_INET, SOCK_DGRAM, 17);
          while (1)
          {
            send("flood", pack("a$size","flood"), 0, pack_sockaddr_in($port, $iaddr));
          }
      });


    sleep $PRE_FLOOD_TIME; # let bbq flood for some time

    $endtime = time() + $PACKET_INTERVAL;
    # now keep flooding but also send "attacks"
    for (my $counter = 0; $counter < $NUM_ATTACKS;) {
      if (time() >= $endtime)
      {
        my $row = 1;
        my @r;
        foreach my $col (0 .. $hlist->cget(-columns) - 1)
        {
          push @r, $hlist->itemCget($row, $col, '-text');
        }

        fire(\@r);

        $counter++;
        $endtime = time() + $PACKET_INTERVAL;
        print "Sent Packet #$counter!\n";
        foreach my $key (keys %{ $additional_data{"1"} })
        {
          if ($key =~ /:sid$/)
          {
            print "SID: ".$additional_data{"1"}{$key}."\n";
            last;
          }
        }
      }
    }
  }

  sub benchmark()
  {
    foreach my $row (0 .. $item_counter - 1)
    {
      my $endtime = time() + 29;
      my @r;
      foreach my $col (0 .. $hlist->cget(-columns) - 1)
      {
        push @r, $hlist->itemCget($row, $col, '-text');
      }
      while (time() <= $endtime)
      {
        fire(\@r);
      }
    }
  }

  sub fire_manual()
  {
    my $height = 100;
    my $width = 300;
    my $win = $mw->Toplevel(-title=>'Fire Manual Rule', -height=>$height, -width=>$width);
    my $main_icon = $mw->Photo( -file => 'icon.gif', -format => 'gif' );
    $win->Icon( -image => $main_icon );

    my $rawIP_icmp = Net::RawIP->new({icmp => {}});
    my $rawIP_tcp  = Net::RawIP->new({tcp  => {}});
    my $rawIP_udp  = Net::RawIP->new({udp  => {}});

    # IP: version, ihl, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr
    $win->Label(-text => 'IP')->grid(-row => 0,-column => 0,-columnspan => 2);

    my $ip_version = "";
    $win->Label(-text => 'version: ')->grid(-row => 1,-column => 0,-sticky=>'e');
    my $entry = $win->Entry(-textvariable => \$ip_version,)->grid(-row => 1,-column => 1);

    my $ip_ihl = "";
    $win->Label(-text => 'ihl: ')->grid(-row => 2,-column => 0,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$ip_ihl,)->grid(-row => 2,-column => 1);

    my $ip_tos = "";
    $win->Label(-text => 'tos: ')->grid(-row => 3,-column => 0,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$ip_tos,)->grid(-row => 3,-column => 1);

    my $ip_tot_len = "";
    $win->Label(-text => 'tot_len: ')->grid(-row => 4,-column => 0,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$ip_tot_len,)->grid(-row => 4,-column => 1);

    my $ip_id = "";
    $win->Label(-text => 'id: ')->grid(-row => 5,-column => 0,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$ip_id,)->grid(-row => 5,-column => 1);

    my $ip_frag_off = "";
    $win->Label(-text => 'frag_off: ')->grid(-row => 6,-column => 0,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$ip_frag_off,)->grid(-row => 6,-column => 1);

    my $ip_ttl = "";
    $win->Label(-text => 'ttl: ')->grid(-row => 7,-column => 0,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$ip_ttl,)->grid(-row => 7,-column => 1);

    my $ip_protocol = "";
    $win->Label(-text => 'protocol: ')->grid(-row => 8,-column => 0,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$ip_protocol,)->grid(-row => 8,-column => 1);

    my $ip_check = "";
    $win->Label(-text => 'check: ')->grid(-row => 9,-column => 0,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$ip_check,)->grid(-row => 9,-column => 1);

    my $ip_saddr = "127.0.0.1";
    $win->Label(-text => 'saddr: ')->grid(-row => 10,-column => 0,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$ip_saddr,)->grid(-row => 10,-column => 1);

    my $ip_daddr = $config{"TARGET_IP"};
    $win->Label(-text => 'daddr: ')->grid(-row => 11,-column => 0,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$ip_daddr,)->grid(-row => 11,-column => 1);

    $win->Label(-text => 'Repeat: ')->grid(-row => 14,-column => 0,-sticky=>'e');
    my $cb_value = "";
    $entry = $win->Checkbox (
    	-variable => \$cb_value,
    	-noinitialcallback => 1,
    	-size => 11,
    )->grid(-row => 14,-column => 1, -sticky=>'w');
    $win->Label(-text => 'Every ')->grid(-row => 15,-column => 0,-sticky=>'e');
    my $repeat_s = "1";
    $win->Entry(-textvariable => \$repeat_s, -width=>8)->grid(-row => 15, -column => 1, -sticky=>'w');
    $win->Label(-text => 's')->grid(-row => 15,-column => 1);
    $win->Label(-text => 'For ')->grid(-row => 16,-column => 0,-sticky=>'e');
    $win->Label(-text => 's')->grid(-row => 16,-column => 1);
    my $repeat_d = "10";
    $win->Entry(-textvariable => \$repeat_d, -width=>8)->grid(-row => 16, -column => 1, -sticky=>'w');

    # TCP: source, dest, seq, ack_seq, doff, res1, res2, urg, ack, psh, rst, syn, fin, window, check, urg_ptr, data
    $win->Label(-text => 'TCP')->grid(-row => 0,-column => 3,-columnspan => 2);

    my $tcp_source = "80";
    $win->Label(-text => 'source: ')->grid(-row => 1,-column => 3,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$tcp_source,)->grid(-row => 1,-column => 4);

    my $tcp_dest = "7777";
    $win->Label(-text => 'dest: ')->grid(-row => 2,-column => 3,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$tcp_dest,)->grid(-row => 2,-column => 4);

    my $tcp_seq = "";
    $win->Label(-text => 'seq: ')->grid(-row => 3,-column => 3,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$tcp_seq,)->grid(-row => 3,-column => 4);

    my $tcp_ack_seq = "";
    $win->Label(-text => 'ack_seq: ')->grid(-row => 4,-column => 3,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$tcp_ack_seq,)->grid(-row => 4,-column => 4);

    my $tcp_doff = "";
    $win->Label(-text => 'doff: ')->grid(-row => 5,-column => 3,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$tcp_doff,)->grid(-row => 5,-column => 4);

    my $tcp_res1 = "";
    $win->Label(-text => 'res1: ')->grid(-row => 6,-column => 3,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$tcp_res1,)->grid(-row => 6,-column => 4);

    my $tcp_res2 = "";
    $win->Label(-text => 'res2: ')->grid(-row => 7,-column => 3,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$tcp_res2,)->grid(-row => 7,-column => 4);

    my $tcp_urg = "";
    $win->Label(-text => 'urg: ')->grid(-row => 8,-column => 3,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$tcp_urg,)->grid(-row => 8,-column => 4);

    my $tcp_ack = "";
    $win->Label(-text => 'ack: ')->grid(-row => 9,-column => 3,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$tcp_ack,)->grid(-row => 9,-column => 4);

    my $tcp_psh = "";
    $win->Label(-text => 'psh: ')->grid(-row => 10,-column => 3,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$tcp_psh,)->grid(-row => 10,-column => 4);

    my $tcp_rst = "";
    $win->Label(-text => 'rst: ')->grid(-row => 11,-column => 3,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$tcp_rst,)->grid(-row => 11,-column => 4);

    my $tcp_syn = "";
    $win->Label(-text => 'syn: ')->grid(-row => 12,-column => 3,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$tcp_syn,)->grid(-row => 12,-column => 4);

    my $tcp_fin = "";
    $win->Label(-text => 'fin: ')->grid(-row => 13,-column => 3,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$tcp_fin,)->grid(-row => 13,-column => 4);

    my $tcp_window = "";
    $win->Label(-text => 'window: ')->grid(-row => 14,-column => 3,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$tcp_window,)->grid(-row => 14,-column => 4);

    my $tcp_check = "0";
    $win->Label(-text => 'check: ')->grid(-row => 15,-column => 3,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$tcp_check,)->grid(-row => 15,-column => 4);

    my $tcp_urg_ptr = "";
    $win->Label(-text => 'urg_ptr: ')->grid(-row => 16,-column => 3,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$tcp_urg_ptr,)->grid(-row => 16,-column => 4);

    my $tcp_data = "";
    $win->Label(-text => 'data: ')->grid(-row => 17,-column => 3,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$tcp_data,)->grid(-row => 17,-column => 4);

    my $tcp_button = $win->Button(
      -text => 'Fire TCP',
      -command=> sub {
        my %ip = ();
        my %proto = ();

        $ip{ip}{version}   = $ip_version  if ($ip_version  ne "");
        $ip{ip}{ihl}       = $ip_ihl      if ($ip_ihl      ne "");
        $ip{ip}{daddr}     = $ip_daddr    if ($ip_daddr    ne "");
        $ip{ip}{tos}       = $ip_tos      if ($ip_tos      ne "");
        $ip{ip}{tot_len}   = $ip_tot_len  if ($ip_tot_len  ne "");
        $ip{ip}{id}        = $ip_id       if ($ip_id       ne "");
        $ip{ip}{frag_off}  = $ip_frag_off if ($ip_frag_off ne "");
        $ip{ip}{ttl}       = $ip_ttl      if ($ip_ttl      ne "");
        $ip{ip}{protocol}  = $ip_protocol if ($ip_protocol ne "");
        $ip{ip}{check}     = $ip_check    if ($ip_check    ne "");
        $ip{ip}{saddr}     = $ip_saddr    if ($ip_saddr    ne "");

        $proto{source}  = $tcp_source   if ($tcp_source  ne "");
        $proto{dest}    = $tcp_dest     if ($tcp_dest    ne "");
        $proto{seq}     = $tcp_seq      if ($tcp_seq     ne "");
        $proto{ack_seq} = $tcp_ack_seq  if ($tcp_ack_seq ne "");
        $proto{doff}    = $tcp_doff     if ($tcp_doff    ne "");
        $proto{res1}    = $tcp_res1     if ($tcp_res1    ne "");
        $proto{res2}    = $tcp_res2     if ($tcp_res2    ne "");
        $proto{urg}     = $tcp_urg      if ($tcp_urg     ne "");
        $proto{ack}     = $tcp_ack      if ($tcp_ack     ne "");
        $proto{psh}     = $tcp_psh      if ($tcp_psh     ne "");
        $proto{rst}     = $tcp_rst      if ($tcp_rst     ne "");
        $proto{syn}     = $tcp_syn      if ($tcp_syn     ne "");
        $proto{fin}     = $tcp_fin      if ($tcp_fin     ne "");
        $proto{window}  = $tcp_window   if ($tcp_window  ne "");
        $proto{check}   = $tcp_check    if ($tcp_check   ne "");
        $proto{urg_ptr} = $tcp_urg_ptr  if ($tcp_urg_ptr ne "");

        my @ws = split(//, $tcp_data);
        my $str = "";
        foreach my $ascii (@ws)
        {
          my $hex_string = unpack "H*", $ascii;
             $hex_string = chr(hex $hex_string);
             $str .= $hex_string;
        }
        $proto{data}    = "$str" if ($tcp_data    ne "");


        $rawIP_tcp->set({
          %ip,
          tcp => { %proto }
        });

        if ($cb_value)
        {
          my $endtime = time() + $repeat_d;
          my $starttime = time();
          while (time() <= $endtime)
          {
            if (time() - $starttime >= $repeat_s)
            {
              $starttime = time();
              $rawIP_tcp->send;
            }
          }
        }
        else
        {
          $rawIP_tcp->send;
        }
      },
    )->grid(
      -row => 18,
      -column => 3,
      -columnspan => 2,
    );


    # ICMP: type, code, check, gateway, id, sequence, unused, mtu, data
    $win->Label(-text => 'ICMP')->grid(-row => 0,-column => 5,-columnspan => 2);

    my $icmp_type = "";
    $win->Label(-text => 'type: ')->grid(-row => 1,-column => 5,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$icmp_type,)->grid(-row => 1,-column => 6);

    my $icmp_code = "";
    $win->Label(-text => 'code: ')->grid(-row => 2,-column => 5,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$icmp_code,)->grid(-row => 2,-column => 6);

    my $icmp_check = "";
    $win->Label(-text => 'check: ')->grid(-row => 3,-column => 5,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$icmp_check,)->grid(-row => 3,-column => 6);

    my $icmp_gateway = "";
    $win->Label(-text => 'gateway: ')->grid(-row => 4,-column => 5,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$icmp_gateway,)->grid(-row => 4,-column => 6);

    my $icmp_id = "";
    $win->Label(-text => 'id: ')->grid(-row => 5,-column => 5,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$icmp_id,)->grid(-row => 5,-column => 6);

    my $icmp_sequence = "";
    $win->Label(-text => 'sequence: ')->grid(-row => 6,-column => 5,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$icmp_sequence,)->grid(-row => 6,-column => 6);

    my $icmp_unused = "";
    $win->Label(-text => 'unused: ')->grid(-row => 7,-column => 5,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$icmp_unused,)->grid(-row => 7,-column => 6);

    my $icmp_mtu = "";
    $win->Label(-text => 'unused: ')->grid(-row => 7,-column => 5,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$icmp_mtu,)->grid(-row => 7,-column => 6);

    my $icmp_data = "";
    $win->Label(-text => 'data: ')->grid(-row => 8,-column => 5,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$icmp_data,)->grid(-row => 8,-column => 6);

    my $icmp_button = $win->Button(
      -text => 'Fire ICMP',
      -command=> sub {
        my %ip = ();
        my %proto = ();

        $ip{ip}{version}   = $ip_version  if ($ip_version  ne "");
        $ip{ip}{ihl}       = $ip_ihl      if ($ip_ihl      ne "");
        $ip{ip}{daddr}     = $ip_daddr    if ($ip_daddr    ne "");
        $ip{ip}{tos}       = $ip_tos      if ($ip_tos      ne "");
        $ip{ip}{tot_len}   = $ip_tot_len  if ($ip_tot_len  ne "");
        $ip{ip}{id}        = $ip_id       if ($ip_id       ne "");
        $ip{ip}{frag_off}  = $ip_frag_off if ($ip_frag_off ne "");
        $ip{ip}{ttl}       = $ip_ttl      if ($ip_ttl      ne "");
        $ip{ip}{protocol}  = $ip_protocol if ($ip_protocol ne "");
        $ip{ip}{check}     = $ip_check    if ($ip_check    ne "");
        $ip{ip}{saddr}     = $ip_saddr    if ($ip_saddr    ne "");

        #type, code, check, gateway, id, sequence, unused, mtu, data
        $proto{type}     = $icmp_type     if ($icmp_type     ne "");
        $proto{code}     = $icmp_code     if ($icmp_code     ne "");
        $proto{check}    = $icmp_check    if ($icmp_check    ne "");
        $proto{gateway}  = $icmp_gateway  if ($icmp_gateway  ne "");
        $proto{id}       = $icmp_id       if ($icmp_id       ne "");
        $proto{sequence} = $icmp_sequence if ($icmp_sequence ne "");
        $proto{unused}   = $icmp_unused   if ($icmp_unused   ne "");
        $proto{data}     = $icmp_data     if ($icmp_data     ne "");

        my @ws = split(//, $icmp_data);
        my $str = "";
        foreach my $ascii (@ws)
        {
          my $hex_string = unpack "H*", $ascii;
             $hex_string = chr(hex $hex_string);
             $str .= $hex_string;
        }
        $proto{data}     = "$str" if ($icmp_data    ne "");


        $rawIP_icmp->set({
          %ip,
          icmp => { %proto }
        });

        if ($cb_value)
        {
          my $endtime = time() + $repeat_d;
          my $starttime = time();
          while (time() <= $endtime)
          {
            if (time() - $starttime >= $repeat_s)
            {
              $starttime = time();
              $rawIP_icmp->send;
            }
          }
        }
        else
        {
          $rawIP_icmp->send;
        }
      },
    )->grid(
      -row => 9,
      -column => 5,
      -columnspan => 2,
    );

    # UDP: source, dest, len, check, data
    $win->Label(-text => 'UDP')->grid(-row => 0,-column => 9,-columnspan => 2);

    my $udp_source = "";
    $win->Label(-text => 'source: ')->grid(-row => 1,-column => 9,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$udp_source,)->grid(-row => 1,-column => 10);

    my $udp_dest = "";
    $win->Label(-text => 'dest: ')->grid(-row => 2,-column => 9,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$udp_dest,)->grid(-row => 2,-column => 10);

    my $udp_len = "";
    $win->Label(-text => 'len: ')->grid(-row => 3,-column => 9,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$udp_len,)->grid(-row => 3,-column => 10);

    my $udp_check = "";
    $win->Label(-text => 'check: ')->grid(-row => 4,-column => 9,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$udp_check,)->grid(-row => 4,-column => 10);

    my $udp_data = "";
    $win->Label(-text => 'data: ')->grid(-row => 5,-column => 9,-sticky=>'e');
    $entry = $win->Entry(-textvariable => \$udp_data,)->grid(-row => 5,-column => 10);

    my $udp_button = $win->Button(
      -text => 'Fire UDP',
      -command=> sub {
        my %ip = ();
        my %proto = ();

        $ip{ip}{version}   = $ip_version  if ($ip_version  ne "");
        $ip{ip}{ihl}       = $ip_ihl      if ($ip_ihl      ne "");
        $ip{ip}{daddr}     = $ip_daddr    if ($ip_daddr    ne "");
        $ip{ip}{tos}       = $ip_tos      if ($ip_tos      ne "");
        $ip{ip}{tot_len}   = $ip_tot_len  if ($ip_tot_len  ne "");
        $ip{ip}{id}        = $ip_id       if ($ip_id       ne "");
        $ip{ip}{frag_off}  = $ip_frag_off if ($ip_frag_off ne "");
        $ip{ip}{ttl}       = $ip_ttl      if ($ip_ttl      ne "");
        $ip{ip}{protocol}  = $ip_protocol if ($ip_protocol ne "");
        $ip{ip}{check}     = $ip_check    if ($ip_check    ne "");
        $ip{ip}{saddr}     = $ip_saddr    if ($ip_saddr    ne "");

        $proto{source} = $udp_source if ($udp_source ne "");
        $proto{dest}   = $udp_dest   if ($udp_dest   ne "");
        $proto{len}    = $udp_len    if ($udp_len    ne "");
        $proto{check}  = $udp_check  if ($udp_check  ne "");

        my @ws = split(//, $udp_data);
        my $str = "";
        foreach my $ascii (@ws)
        {
          my $hex_string = unpack "H*", $ascii;
             $hex_string = chr(hex $hex_string);
             $str .= $hex_string;
        }
        $proto{data}     = "$str" if ($udp_data    ne "");


        $rawIP_udp->set({
          %ip,
          udp => { %proto }
        });

        if ($cb_value)
        {
          my $endtime = time() + $repeat_d;
          my $starttime = time();
          while (time() <= $endtime)
          {
            if (time() - $starttime >= $repeat_s)
            {
              $starttime = time();
              $rawIP_udp->send;
            }
          }
        }
        else
        {
          $rawIP_udp->send;
        }
      },
    )->grid(
      -row => 6,
      -column => 9,
      -columnspan => 2,
    );
  }

  sub fire()
  {
    my @infos = @{$_[0]};

    my $minsize = 2000;

    my $id       =                $infos[0];
    my $action   = translate_vars($infos[1]);
    my $protocol = translate_vars($infos[2]);
    my $src_ip   = translate_vars($infos[3]);
    my $src_port = translate_vars($infos[4]);
    my $dir      = translate_vars($infos[5]);
    my $dst_ip   = translate_vars($infos[6]);
    my $dst_port = translate_vars($infos[7]);
    my $msg      = translate_vars($infos[8]);

    # protocols can't be changed later, so we have to create seperate objects
    my $rawIP_icmp = Net::RawIP->new({icmp => {}});
    my $rawIP_tcp  = Net::RawIP->new({tcp  => {}});
    my $rawIP_udp  = Net::RawIP->new({udp  => {}});

    my $from_server = 0;

    $src_ip = $local_ip if ($src_ip eq "any");

    # Remove CIDR notation if existing
    $src_ip = (split(/\//, $src_ip))[0] if ($src_ip =~ /\//);
    $dst_ip = (split(/\//, $dst_ip))[0] if ($dst_ip =~ /\//);

    print "SRC IP: $src_ip\n";

    # Set the destination to TARGET_IP, which is no problem if the destination is "any".
    # Otherwise, the user has been warned.
    $dst_ip = $config{"TARGET_IP"};

    $src_port = COMM_PORT if ($src_port eq "any");
    $src_port =~ s/\:.*//;
    if ($src_port =~ /!/)
    {
      $src_port = (split(/!/, $src_port))[1] + 1;
    }
    print "srcport: $src_port\n";

    # Set destination port to COMM_PORT if we can, so we don't have to request
    # the receiver to bind a second port if a handshake was required
    $dst_port = COMM_PORT if ($dst_port eq "any");
    $dst_port =~ s/\:.*//;
    if ($dst_port =~ /!/)
    {
      $dst_port = (split(/!/, $dst_port))[1] + 1;
    }
    print "dst: $dst_ip:$dst_port\n";

    my %ip = ( ip => { saddr => $src_ip, daddr => $dst_ip } );

    my %proto = ();
       %proto = ( source => $src_port, dest => $dst_port, check => 0 ) if ($protocol ne "icmp");

    my $ttl = 255;
    my $handshake = 0;
    my $payload = "";
    my $repeat = 1;
    my $doe = 0;
    my $length_last_content = 0;
    my $is_uri = 0;
    my $uri_count = 0;
    foreach my $key ( sort { (split(/:/, $a))[0] <=> (split(/:/, $b))[0] } keys %{ $additional_data{$id} })
    {
      print "PARSING $key #######################\n\n";
      my $add_data = $additional_data{$id}{$key};

      if ($key =~ /:uricontent/)
      {
        #$add_data = "&".$add_data if ($uri_count > 0 && substr($add_data, 0, 1) ne "!");
        $is_uri = "GET" if (!$is_uri);
        $uri_count++;
      }
      # CONTENT (also applies to uri_content)
      if ($key =~ /content$/)
      {
        my $str = (split(/\"/, $add_data))[0];
           $str =~ s/^\s+//;
        my $neg = $str eq "!";
        $add_data =~ s/\"//g;

        if (($add_data eq "POST" || $add_data eq "GET"))
        {
          $is_uri = $add_data;
          next;
        }

        $length_last_content = 0;
        print "got $key: $add_data\n";
        if ($add_data =~ /\|/)
        {
          my @spl = split (/\|/, $add_data);
          my $is_hex = 0;
          foreach my $s (@spl)
          {
            print "char is $s\n";
            if ($s eq "")
            {
              $is_hex = 1;
              next;
            }
            if ($is_hex == 1)
            {
              my @ws = split(/ /, $s);
              foreach my $hex (@ws)
              {
                print "hex $s to \"".chr(hex $hex)."\"\n";
                # Translate hex
                my $new_str = chr(hex $hex);
                if ($neg)
                {
                  if ($new_str ne "x")
                  {
                    $new_str = "x";
                  }
                  else
                  {
                    $new_str = "y";
                  }
                }
                if ($doe == length($payload))
                {
                  $payload .= $new_str;
                }
                else
                {
                  substr($payload, $doe, length($new_str), $new_str);
                }
                $length_last_content ++;
                $doe ++;
              }
            }
            else
            {
              my @ws = split(//, $s);
              foreach my $ascii (@ws)
              {
                my $hex_string = unpack "H*", $ascii;
                $hex_string = chr(hex $hex_string);
                # Translate hex

                if ($neg)
                {
                  if ($hex_string ne "x")
                  {
                    $hex_string = "x";
                  }
                  else
                  {
                    $hex_string = "y";
                  }
                }

                if ($doe == length($payload))
                {
                  $payload .= $hex_string;
                }
                else
                {
                  substr($payload, $doe, length($hex_string), $hex_string);
                }
                $length_last_content ++;
                $doe ++;
              }

              print "Payload is now \"".$payload."\"\n";
            }
            $is_hex = !$is_hex;
          }
        }
        else
        {
          print "Payload \"$add_data\" has no hex data.\n";
          my @ws = split(//, $add_data);
          foreach my $ascii (@ws)
          {
            my $hex_string = unpack "H*", $ascii;
               $hex_string = chr(hex $hex_string);
            # Translate hex

            if ($neg)
            {
              if ($hex_string ne "x")
              {
                $hex_string = "x";
              }
              else
              {
                $hex_string = "y";
              }
            }

            if ($doe == length($payload))
            {
              $payload .= $hex_string;
            }
            else
            {
              substr($payload, $doe, length($hex_string), $hex_string);
            }
            $length_last_content ++;
            $doe ++;
          }
        }
        print "end of content. DOE: $doe\n";
          print "TCP payload: ".$payload."\n";
      }
      elsif ($key =~ /offset/)
      {
        print "offset key: $key\n";
        print "offset: $add_data\n";
        print "payload: $payload\n";
        print "doe: $doe\n";
        print "llc: $length_last_content\n";

        if ($add_data < $doe)
        {
          #my $last_content = substr($payload, $doe-$length_last_content, $length_last_content, "");
          #substr($payload, $add_data, $length_last_content, $last_content);
          $payload .= "x" x $add_data . $payload;
        }
        else
        {
          # if our content has byte_test data added, this counts aswell
          my $diff = $add_data + $length_last_content - $doe;
          print "diff: $diff\n";
          substr($payload, $doe - $length_last_content, 0, 'x' x $diff) if ($diff > 0);
          print "new content: $payload\n";
        }
        $doe = $add_data + $length_last_content;
      }
      elsif ($key =~ /distance/)
      {
        print "DISTANCE\n";
        print "payload: \"$payload\"\n";
        print "doe: $doe\n";
        print "length last content: $length_last_content\n";
        my $last_content = substr($payload, $doe - $length_last_content, $length_last_content, "");
        print "last content: \"$last_content\"\n";
        if ($add_data > 0)
        {
          substr($payload, $doe - $length_last_content, $length_last_content + $add_data, 'x' x $add_data . $last_content);
        }
        else
        {
          substr($payload, $doe + $add_data - $length_last_content, $length_last_content, $last_content);
        }
        print "payload: \"$payload\"\n";
        $doe += $add_data;
      }
      elsif ($key =~ /byte_test/)
      {
        print "Got byte_test\n";
        my @btest = split(/,/, $add_data);
        my $bytes_to_convert = $btest[0];
        my $operator = $btest[1];
        my $value = $btest[2];
        my $offset = $btest[3];

        if ($add_data =~ /relative/)
        {
          $doe += $offset;
        }
        else
        {
          $doe = $offset;
        }

        # TODO: [,relative] [,<endian>] [,<number type>, string]
        my $fake;
        if ($operator =~ /=/)
        {
          $fake = $value;
        }
        elsif ($operator =~ /</)
        {
          $fake = $value - 1;
        }
        elsif ($operator =~ />/)
        {
          $fake = $value + 1;
        }
        elsif ($operator =~ /&/ || /^/)
        {
           # AND can only be true if 1 & 1
           # OR is always true if a 1 occurs
          $fake = "1";
        }

        if (length($payload) < $doe)
        {
          my $diff = $doe - length($payload);
          substr ($payload, $doe - $diff, 0, "x" x $diff);
        }

        $fake = sprintf("%X", $fake) if ($add_data =~ /string/);
        my $zeroes = $bytes_to_convert * 2 - length($fake);
        $fake = "0" x $zeroes . $fake;

        if ($add_data !~ /string/)
        {
          my @hex_fake = ( $fake =~ m/../g );
          $fake = pack 'H2' x @hex_fake, @hex_fake;
        }

        substr ($payload, $doe, 0, $fake);
        print "l_fake: ".length($fake)."\n";
        $doe += length($fake);
        print "new payload: $payload\n";
        print "doe: $doe\n";
      }
      elsif ($key =~ /byte_jump/)
      {
        # byte_jump reads $byte_length bytes at $offset and jumps that far
        print "Got $key\n";
        my $byte_length = (split(/,/, $add_data))[0];
        my $offset = (split(/,/, $add_data))[1];

        if ($add_data =~ /relative/)
        {
          $doe += $offset;
        }
        else
        {
          $doe = $offset;
        }

        if (length($payload) < $doe)
        {
          my $diff = $doe - length($payload);
          print "doe: $doe, len_payload: ".length($payload)." diff: $diff\n";
          substr ($payload, $doe - $diff, 0, "x" x $diff);
        }

        # workaround: we jump 20 bytes which should be enough for most (or all) negative offsets to come
        #             if for example the next byte_test has an offset of 0, this is a waste of space
        my $jump = "\x00" x ($byte_length - 1) . "\x14";
           $jump = "0" x ($byte_length - 1) . "20" if ($add_data !~ /string/);
        substr ($payload, $doe, 0, $jump);
        $doe += $byte_length;
        print "filling 20bytes from $doe\n";
        # now fill the bytes we skipped
        substr ($payload, $doe, 0, "x" x 20);
        $doe += 20;
        print "new payload: $payload\n";
      }
      # TIME TO LIVE
      elsif ($key =~ /ttl/)
      {
        $ttl = $add_data;
        if ($add_data =~ s/^\D+//s)
        {
          # {<, >, >=, <=}ttl
          if ($& eq ">")
          {
             $ttl = 255; # just go with max value
          }
          elsif ($& eq "<")
          {
             $ttl -= 1; # highest allowed value
          }
        }
        $ip{ip}->{ttl} = $ttl;
      }
      # ICMP CODE
      elsif ($key =~ /icode/)
      {
        if ($add_data =~ /<>/)
        {
          my @spl = split(/>/, $add_data);
          $proto{code} = $spl[1];
        }
        elsif ($add_data =~ />/)
        {
          my @spl = split(/>/, $add_data);
          $proto{code} = $spl[1] + 1;
        }
        elsif ($add_data =~ /</)
        {
          my @spl = split(/</, $add_data);
          $proto{code} = $spl[1] - 1;
        }
        else
        {
          $proto{code} = $add_data;
        }
      }
      elsif ($key =~ /:threshold/)
      {
        # rules with the threshold keyword may either alert only after x matches,
        # or up until x matches. To trigger former rules, our packet has to be
        # sent multiple times.
        # The documentation says this is tracked by unique ip, but starting
        # seperate sessions works aswell. Otherwise this would be impossible
        # in combination with the established keyword, as we can't spoof the
        # TCP Handshake
        my @spl = split(/,/, $add_data);
        for (my $i; $i < scalar(@spl); $i++)
        {
          $spl[$i] =~ s/^ *//g;
        }
        my $type = (split (/ /, $spl[0]))[1];
        my $count =  (split (/ /, $spl[2]))[1];
        print "count: $count\n";
        $repeat = $count if ($type =~ /threshold/ || $type =~ /both/);
        print "threshold repetition: $repeat\n";
      }
      # ICMP TYPE
      elsif ($key =~ /:itype/)
      {
        if ($add_data =~ /<>/)
        {
          my @spl = split(/>/, $add_data);
          $proto{type} = $spl[1];
        }
        elsif ($add_data =~ />/)
        {
          my @spl = split(/>/, $add_data);
          $proto{type} = $spl[1] + 1;
        }
        elsif ($add_data =~ /</)
        {
          my @spl = split(/</, $add_data);
          $proto{type} = $spl[1] - 1;
        }
        else
        {
          $proto{type} = $add_data;
        }
      }
      # TCP FLAGS
      elsif ($key =~ /:flags/)
      {
        # See http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node33.html#SECTION00468000000000000000
        # Bit 1 = C (CWR) and 2 = E (ECE)

        if ($add_data =~ /,/)
        {
          # Flags can be given as e.g. "S,CE", which means: check for SYN bit, but ignore the reserved bits (CE)
          my @spl = split (/,/, $add_data);
          foreach my $d (@spl)
          {
            print "FLAGS: $d\n";
          }
          $add_data = $spl[0];
        }

        if ($add_data =~ /S/)
        {
          print "Set SYN flag\n";
          $rawIP_tcp->set({ tcp => {syn => 1} });
        }
        if ($add_data =~ /A/)
        {
          print "Set ACK flag\n";
          $rawIP_tcp->set({ tcp => {ack => 1} });
        }
        if ($add_data =~ /F/)
        {
          print "Set FIN flag\n";
          $rawIP_tcp->set({ tcp => {fin => 1} });
        }
        if ($add_data =~ /R/)
        {
          print "Set RST flag\n";
          $rawIP_tcp->set({ tcp => {rst => 1} });
        }
        if ($add_data =~ /P/)
        {
          print "Set PSH flag\n";
          $rawIP_tcp->set({ tcp => {psh => 1} });
        }
        if ($add_data =~ /U/)
        {
          print "Set URG flag\n";
          $rawIP_tcp->set({ tcp => {urg => 1} });
        }

        my $cwr_ece = 0;
        if ($add_data =~ /E/ || $add_data =~ /2/)
        {
          print "Set ECE flag\n";
          $cwr_ece = 1;
        }
        if ($add_data =~ /C/ || $add_data =~ /1/)
        {
          # res2 is two bits wide: res2 = 1 => ECE, res2 = 2 => CWR, res2 = 3 => ECE + CWR
          if ($cwr_ece == 1)
          {
            print "Set ECE+CWR flags\n";
            $cwr_ece = 3;
          }
          else
          {
            print "Set CWR flag\n";
            $cwr_ece = 2;
          }
        }
        $rawIP_tcp->set({ tcp => {res2 => $cwr_ece} });
      }
      elsif ($key =~ /fragbits/)
      {
        # RawIP sets the ip flags via the fragment offset (frag_off)
        # Flags are 3 bits wide and the offset is 13 bits -> 16 bits total
        # Flags are Bit 0: Reserved, Bit 1: Don't Fragment (DF), Bit 2: More Fragments (MF)

        # R  DF MF < --  F R A G M E N T   O F F S E T  -->
        # 0  0  0  0   0  0  0  0   0  0  0  0   0  0  0  0

        next if ($add_data =~ /!/);
        my $m = 0;
        my $d = 0;
        my $r = 0;

        $m = 1 if $add_data =~ /M/;
        $d = 1 if $add_data =~ /D/;
        $r = 1 if $add_data =~ /R/;
        my $rdm = $r . $d . $m . "0" x 13;
        my $val = oct("0b" . $rdm);

        $ip{ip}{frag_off} = $val;
      }
      elsif ($key =~ /:ip_proto$/)
      {
        # look protocols up in /etc/protocols
        # Note: this is platform dependent

        open(my $fh, '<:encoding(UTF-8)', "/etc/protocols")
          or die "Could not open protocols file: $!";

        my %protocols = ();

        while (my $row = <$fh>) {
          my @r = split (/\t| /, $row);
          next if ($r[0] eq "#");
          $protocols{$r[0]} = $r[1];
        }

        close($fh);

        my $val = $add_data;

        # Format: ip_proto:[!|>|<] <name or number>;
        $val = (split(/</, $add_data))[1] if ($add_data =~ /</);
        $val = (split(/>/, $add_data))[1] if ($add_data =~ />/);
        $val = (split(/!/, $add_data))[1] if ($add_data =~ /!/);

        if ( $val !~ /^[0-9,.E]+$/ ) # NaN -> find protocol number
        {
          if (exists $protocols{$val})
          {
            $val = $protocols{$val};
          }
          else
          {
            print "[ERROR] Can't resolve protocol \"$val\"\n";
            next;
          }
        }

        # val now stores the protocol number
        if ($add_data =~ /!/)
        {
          foreach my $p (values %protocols)
          {
            if ($p != $val)
            {
              $ip{ip}{protocol} = $p;
              last;
            }
          }
        }
        elsif ($add_data =~ />/)
        {
          foreach my $p (values %protocols)
          {
            if ($p > $val)
            {
              $ip{ip}{protocol} = $p;
              last;
            }
          }
        }
        elsif ($add_data =~ /</)
        {
          foreach my $p (values %protocols)
          {
            if ($p < $val)
            {
              $ip{ip}{protocol} = $p;
              last;
            }
          }
        }
        else
        {
          $ip{ip}{protocol} = $val;
        }
      }
      # ACKNOWLEDGEMENT (TCP)
      elsif ($key =~ /:ack/)
      {
        $rawIP_tcp->set({ tcp => {ack_seq => $add_data} });
      }
      # SEQUENCE NUMBER (TCP)
      elsif ($key =~ /:seq/)
      {
        $rawIP_tcp->set({ tcp => {seq => $add_data} });
      }
      elsif ($key =~ /:dsize/)
      {
         print "[WARNING] Payload too big. Sending this packet will probably fail.\n" if ($add_data >= 1470);
         # TODO: maybe try using sockets in this case if we can

         if ($add_data =~ /<>/)
         {
           $payload .= "x" x ((split(/<>/, $add_data))[1] - length($payload));
         }
         elsif ($add_data =~ /</)
         {
           $payload .= "x" x ((split(/</, $add_data))[1] - 1 - length($payload));
         }
         elsif ($add_data =~ />/)
         {
           $payload .= "x" x ((split(/>/, $add_data))[1] + 1 - length($payload));
         }
         else
         {
           $payload .= "x" x ($add_data - length($payload));
         }
      }
      elsif ($key =~ /:id$/)
      {
          $ip{ip}->{id} = $add_data;
      }
      elsif ($key =~ /:window/)
      {
          my $win = $add_data;
          if ($add_data =~ /!/)
          {
            $win = (split (/!/, $add_data))[1];
            $win = $win eq "20" ? "10" : "20";
          }
          $rawIP_tcp->set({ tcp => {window => $win} });
      }
      # FLOW
      # flow:[(established|not_established|stateless)]
      #      [,(to_client|to_server|from_client|from_server)]
      #      [,(no_stream|only_stream)]
      #      [,(no_frag|only_frag)];
      elsif ($key =~ /:flow$/)
      {
        print "flowdata: $add_data\n";
        if ($add_data =~ /established/) # equal to flag "+A"
        {
          # A TCP Hanshake is mandatory for this rule to trigger
          # set the handshake flag for this to be handled before the packet is sent
          $handshake = 1;
          $from_server = 0;
        }
        if ($add_data =~ /from_server/ || $add_data =~ /to_client/)
        {
          $from_server = 1;
        }
      }
      elsif ($key =~ /:flowbits$/)
      {
        print "Rule has flowbits.\n";
        if ($add_data =~ /isset/)
        {
          my @d = split(/,/, $add_data);
          my $bit = $d[1];
          if ($flowbits_set{$bit})
          {
            print "Needs $bit\n";
            print "ID: ".$flowbits_set{$bit}[0]."\n";
          }
        }
      }
      elsif ($key =~ /:icmp_id$/)
      {
        $proto{id} = $add_data;
      }
      # MESSAGE
      elsif ($key =~ /:msg/)
      {
        # irrelevant to packet
        print "$add_data\n";
        next;
      }
      else
      {
        print "[WARNING] Rule option \"$key\" is not supported.\n";
      }
    }
    if ($minsize > 0)
    {
      print "Payload is \"$payload\"\n";
      print "Extending by ".($minsize - length($payload))."\n";
      $payload .= "x" x ($minsize - length($payload));
        print "Payload is \"$payload\"\n";
    }

    $payload = "" if (length($payload) >= 1470);
    $proto{data} = $payload;

    for (my $i = 0; $i < $repeat; $i++)
    {
      if ($protocol eq "tcp" || $protocol eq "ip")
      {
          $rawIP_tcp->set({
            %ip,
            tcp => { %proto }
          });

          print "Target is: ".$ip{ip}{saddr}.":".$proto{source}."\n";
          foreach my $key (keys %{ $additional_data{"1"} })
          {
            if ($key =~ /:sid$/)
            {
              print "SID: ".$additional_data{"1"}{$key}."\n";
              last;
            }
          }
          if (!$handshake && !$from_server)
          {
            $rawIP_tcp->send;
            print "Sent TCP packet.\n";
          }
          else
          {
            print "Requiring handshake.\nFrom_server: $from_server\n";
            send_request($rawIP_tcp, $from_server, $handshake, $is_uri);
          }
      }
      elsif ($protocol eq "udp")
      {
          print "payload: ".$proto{data}."\n";
          $rawIP_udp->set({
            %ip,
            udp => { %proto }
          });
          $rawIP_udp->send;
          print "Sent UDP packet to $dst_ip\n";
      }
      elsif ($protocol eq "icmp")
      {
          $rawIP_icmp->set({
            %ip,
            icmp => { %proto }
          });
          $rawIP_icmp->send;
          print "Sent ICMP packet to $dst_ip\n";
      }
      else
      {
        print "[ERROR] unsupported protocol \"$protocol\".\n";
        return;
      }
    }
  }

  # used to translate values like $HOME_NET to respective IP(s) or port(s)
  sub translate_vars()
  {
    my $val = shift;
       $val =~ s/\[//; # e.g. [$HTTP_PORTS,443]
       $val =~ s/\]//;
       $val =~ s/,.*//;
    if ($val =~ s/\$//s)
    {
      my $ret = $config{$val};
      if (ref($config{$val}) eq "ARRAY")
      {
         # choose a random value from the array (e.g. a port from $HTTP_PORTS)
         $ret = $config{$val}[rand @{$config{$val}}];
      }
      # translate CIDR notation to first ip (e.g. 192.168.0.0/16 to 192.168.0.0)
      $ret = $config{$val} =~ /^([^\/]+)/ if ($val =~ /\//);
      return $ret;
    }
    else
    {
      return $val;
    }
  }

  sub open_settings()
  {
    my $height = 100;
    my $width = 300;
    my $win = $mw->Toplevel(-title=>'Settings', -height=>$height, -width=>$width);
    my $main_icon = $mw->Photo( -file => 'icon.gif', -format => 'gif' );
    $win->Icon( -image => $main_icon );

    my $target_ip      = $config{"TARGET_IP"};
    my $interface      = $config{"INTERFACE"};
    my $home_net       = $config{"HOME_NET"};
    my $external_net   = $config{"EXTERNAL_NET"};
    my $dns_servers    = $config{"DNS_SERVERS"};
    my $smtp_servers   = $config{"SMTP_SERVERS"};
    my $http_servers   = $config{"HTTP_SERVERS"};
    my $sql_servers    = $config{"SQL_SERVERS"};
    my $telnet_servers = $config{"TELNET_SERVERS"};
    my $ssh_servers    = $config{"SSH_SERVERS"};
    my $ftp_servers    = $config{"FTP_SERVERS"};
    my $sip_servers    = $config{"SIP_SERVERS"};

    my $http_ports      = $config{"HTTP_PORTS"};
    my $shellcode_ports = $config{"SHELLCODE_PORTS"};
    my $oracle_ports    = $config{"ORACLE_PORTS"};
    my $ssh_ports       = $config{"SSH_PORTS"};
    my $ftp_ports       = $config{"FTP_PORTS"};
    my $sip_ports       = $config{"SIP_PORTS"};
    my $file_data_ports = $config{"FILE_DATA_PORTS"};
    my $gtp_ports       = $config{"GTP_PORTS"};
    my $aim_servers     = $config{"AIM_SERVERS"};

    $win->Label(-text => 'Target IP: ')->grid(-row => 0,-column => 0,-sticky=>'e');
    my $entry = $win->Entry(-textvariable => \$target_ip,)->grid(-row => 0,-column => 1);

    my $err;
    my %devinfo;
    my @devs = pcap_findalldevs(\%devinfo, \$err);
    if (!defined $err)
    {
      $win->Label(-text => 'Interface: ')->grid(-row => 1,-column => 0,-sticky=>'e');
      my $jcb = $win->JComboBox(
        -entrywidth => 16.7,
        -relief => "sunken",
        -textvariable => \$interface
      )->grid(-row => 1,-column => 1);

      for my $dev (@devs) {
        $jcb->addItem($dev);
      }

      $jcb->setSelected($config{"INTERFACE"});
      $jcb->focus;
    }
    $win->Label(-text => '$HOME_NET: ')->grid(-row => 2,-column => 0,-sticky=>'e');
    $win->Entry(-textvariable => \$home_net)->grid(-row => 2,-column => 1);

    $win->Label(-text => '$EXTERNAL_NET: ')->grid(-row => 3,-column => 0,-sticky=>'e');
    $win->Entry(-textvariable => \$external_net)->grid(-row => 3,-column => 1);

    $win->Label(-text => '$DNS_SERVERS: ')->grid(-row => 4,-column => 0,-sticky=>'e');
    $win->Entry(-textvariable => \$dns_servers)->grid(-row => 4,-column => 1);

    $win->Label(-text => '$SMTP_SERVERS: ')->grid(-row => 5,-column => 0,-sticky=>'e');
    $win->Entry(-textvariable => \$smtp_servers)->grid(-row => 5,-column => 1);

    $win->Label(-text => '$HTTP_SERVERS: ')->grid(-row => 6,-column => 0,-sticky=>'e');
    $win->Entry(-textvariable => \$http_servers)->grid(-row => 6,-column => 1);

    $win->Label(-text => '$SQL_SERVERS: ')->grid(-row => 7,-column => 0,-sticky=>'e');
    $win->Entry(-textvariable => \$sql_servers)->grid(-row => 7,-column => 1);

    $win->Label(-text => '$TELNET_SERVERS: ')->grid(-row => 8,-column => 0,-sticky=>'e');
    $win->Entry(-textvariable => \$telnet_servers)->grid(-row => 8,-column => 1);

    $win->Label(-text => '$SSH_SERVERS: ')->grid(-row => 9,-column => 0,-sticky=>'e');
    $win->Entry(-textvariable => \$ssh_servers)->grid(-row => 9,-column => 1);

    $win->Label(-text => '$FTP_SERVERS: ')->grid(-row => 10,-column => 0,-sticky=>'e');
    $win->Entry(-textvariable => \$ftp_servers)->grid(-row => 10,-column => 1);

    $win->Label(-text => '$SIP_PORTS: ')->grid(-row => 11,-column => 0,-sticky=>'e');
    $win->Entry(-textvariable => \$sip_ports)->grid(-row => 11,-column => 1);

    $win->Label(-text => '$HTTP_PORTS: ')->grid(-row => 12,-column => 0,-sticky=>'e');
    $win->Entry(-textvariable => \$http_ports)->grid(-row => 12,-column => 1);

    $win->Label(-text => '$SHELLCODE_PORTS: ')->grid(-row => 13,-column => 0,-sticky=>'e');
    $win->Entry(-textvariable => \$shellcode_ports)->grid(-row => 13,-column => 1);

    $win->Label(-text => '$ORACLE_PORTS: ')->grid(-row => 14,-column => 0,-sticky=>'e');
    $win->Entry(-textvariable => \$oracle_ports)->grid(-row => 14,-column => 1);

    $win->Label(-text => '$SSH_PORTS: ')->grid(-row => 15,-column => 0,-sticky=>'e');
    $win->Entry(-textvariable => \$ssh_ports)->grid(-row => 15,-column => 1);

    $win->Label(-text => '$FTP_PORTS: ')->grid(-row => 16,-column => 0,-sticky=>'e');
    $win->Entry(-textvariable => \$ftp_ports)->grid(-row => 16,-column => 1);

    $win->Label(-text => '$SIP_PORTS: ')->grid(-row => 17,-column => 0,-sticky=>'e');
    $win->Entry(-textvariable => \$sip_ports)->grid(-row => 17,-column => 1);

    $win->Label(-text => '$FILE_DATA_PORTS: ')->grid(-row => 18,-column => 0,-sticky=>'e');
    $win->Entry(-textvariable => \$file_data_ports)->grid(-row => 18,-column => 1);

    $win->Label(-text => '$GTP_PORTS: ')->grid(-row => 19,-column => 0,-sticky=>'e');
    $win->Entry(-textvariable => \$gtp_ports)->grid(-row => 19,-column => 1);

    $win->Label(-text => '$AIM_SERVERS: ')->grid(-row => 20,-column => 0,-sticky=>'e');
    $win->Entry(-textvariable => \$aim_servers)->grid(-row => 20,-column => 1);

    my $button = $win->Button(
    	-text => 'OK',
    	-command=> sub {
        $config{"TARGET_IP"}       = $target_ip;
        $config{"INTERFACE"}       = $interface;
        $config{"HOME_NET"}        = $home_net;
        $config{"EXTERNAL_NET"}    = $external_net;
        $config{"DNS_SERVERS"}     = $dns_servers;
        $config{"SMTP_SERVERS"}    = $smtp_servers;
        $config{"HTTP_SERVERS"}    = $http_servers;
        $config{"SQL_SERVERS"}     = $sql_servers;
        $config{"TELNET_SERVERS"}  = $telnet_servers;
        $config{"SSH_SERVERS"}     = $ssh_servers;
        $config{"FTP_SERVERS"}     = $ftp_servers;
        $config{"SIP_SERVERS"}     = $sip_servers;
        $config{"HTTP_PORTS"}      = $http_ports;
        $config{"SHELLCODE_PORTS"} = $shellcode_ports;
        $config{"ORACLE_PORTS"}    = $oracle_ports;
        $config{"SSH_PORTS"}       = $ssh_ports;
        $config{"FTP_PORTS"}       = $ftp_ports;
        $config{"SIP_PORTS"}       = $sip_ports;
        $config{"FILE_DATA_PORTS"} = $file_data_ports;
        $config{"GTP_PORTS"}       = $gtp_ports;
        $config{"AIM_SERVERS"}     = $aim_servers;
        write_config();

        $win->destroy;
      },
    )->grid(
    	-row => 100,
    	-column => 0,
    	-columnspan => 2,
    );
  }

  my $tmp_socket;
  sub send_request
  {
    my $raw_tcp = shift;
    my $from_server = shift;
    my $established = shift;
    my $http = shift;

    my %ipinfos = %{$raw_tcp->get({ip => [qw(saddr daddr)]})};
    my %tcpinfos = %{$raw_tcp->get({tcp => [qw(source dest data)]})};

    my $src_host = join '.', unpack 'C4', pack 'N', $ipinfos{saddr};
    my $src_port = $tcpinfos{source};

    my $dst_host = join '.', unpack 'C4', pack 'N', $ipinfos{daddr};
    my $dst_port = $tcpinfos{dest};

    my $payload = $tcpinfos{data};
    print "payload: $payload\n";

    print "saddr: $src_host\n";
    print "daddr: $dst_host\n";

    my $socket = new IO::Socket::INET (
      PeerHost => $config{"TARGET_IP"},
      PeerPort => COMM_PORT,
      Proto => 'tcp',
    );
    die "cannot connect to portmapper $!\n" unless $socket;
    print "connected to portmapper\n";

    if (!$from_server && $established)
    {
        my $retry = 1;
        $dst_port = 8888 if ($dst_port eq COMM_PORT && $http);
        if ($dst_port ne COMM_PORT || $http)
        {
          my $req =  "open:".$dst_port;
             $req .= ";is_http" if ($http);
          $socket->send($req);
          print "sent request: $req\n";
          my $resp = "";
          $socket->recv($resp, 1024); # wait for server to open socket
          print "response: $resp\n";
          if ($resp eq "OK")
          {
            print "Port is now open.\n"
          }
          else
          {
            print "[WARNING] Problem while opening port.\n";
          }
        }

        if ($http)
        {
          print "Requesting HTTP\n";
          my $ua = LWP::UserAgent->new;
             $ua->agent("BBQ/1.0 ");

          my $uri = normalize_uri($payload);
          $uri =~ s/^.// if ((split(//, $uri))[0] eq "/");

          my $req;
             $req = HTTP::Request->new(GET  => 'http://'.$config{"TARGET_IP"}.":$dst_port/$uri");
             $req = HTTP::Request->new(POST => 'http://'.$config{"TARGET_IP"}.":$dst_port/$uri") if ($http eq "POST");
          print "HTTP RESPONSE: ". $ua->request($req)."\n";
        }
        else
        {
          print "\ntrying to connect to $dst_port...";
          my $err = '';
          $pcap = pcap_open_live("eth0", 1024, 0, 0, \$err)
            or die "Can't open device eth0: $err\n";
          while($retry)
          {
              $retry = 0;
              my ($sock);
              socket($sock, AF_INET, SOCK_STREAM, getprotobyname('tcp')) || die $!;
              bind($sock, pack_sockaddr_in($src_port, (gethostbyname($src_host))[4]));
              my $paddr = sockaddr_in($dst_port, (gethostbyname($dst_host))[4]);
              connect($sock, $paddr) or $retry = 1;
              pcap_loop($pcap, -1, \&process_packet, \%tcpinfos) if (!$retry);
          }
          print "\n";

          pcap_close($pcap);
      }
    }
    elsif ($from_server && !$established)
    {
      my ($sock);
      if ($dst_port ne COMM_PORT)
      {
        socket($sock, AF_INET, SOCK_STREAM, getprotobyname('tcp')) || die $!;
        bind($sock, pack_sockaddr_in($dst_port, (gethostbyname($local_ip))[4]));
      }
      $socket->send("send_raw:$src_host,$src_port,$local_ip,$dst_port,".encode_base64($payload, ''));
      close ($sock) if ($dst_port ne COMM_PORT && $sock);
    }
    elsif ($from_server && $established)
    {
      my ($sock);
      socket($sock, AF_INET, SOCK_STREAM, getprotobyname('tcp')) || die $!;
      bind($sock, pack_sockaddr_in($dst_port, (gethostbyname($local_ip))[4]));
      my $resp = "";
      print "send:$src_port,$payload\n";
      $socket->send("send:$src_port,".encode_base64($payload, ''));
      $socket->recv($resp, 1024); # wait for server to open socket
      print "response: $resp\n";
      if ($resp eq "OK")
      {
        my $paddr = sockaddr_in($src_port, (gethostbyname($dst_host))[4]);
        print "trying to connect to $dst_host:$src_port... ";
        connect($sock, $paddr) or die "connection failed: $!";

        print "OK\n";
      #  sleep(0.3);
        shutdown($sock, 2);
      }
      close($sock);

    }
    # !$from_server && !$established won't end up in this subroutine

    $socket->close;
  }

  sub process_packet
  {
    my ($user_data, $header, $packet) = @_;
    my $payload = %{$user_data}{data};

    # Note: we should probably make sure that the syn-ack is actually sent from our target
    my $synack_eth 	= NetPacket::Ethernet->decode($packet);
    my $sa_ip  	= NetPacket::IP->decode($synack_eth->{data});
    my $synack = NetPacket::TCP->decode($sa_ip->{data});

    if ($synack->{flags} eq "18") # SYN-ACK
    {
      print "Got SYN-ACK from ". $sa_ip->{src_ip}."\n";
      print "Sequence Number: ".$synack->{seqnum}."\n";
      print "Arrived at ".$sa_ip->{dest_ip}.":". $synack->{dest_port}."\n";
      print "Target: ".$sa_ip->{src_ip}.":".%{$user_data}{dest}."\n";
      print "Payload: $payload\n";

      my $n = Net::RawIP->new({
         ip  => {
                 saddr => $sa_ip->{dest_ip},
                 daddr => $sa_ip->{src_ip},
                },
         tcp => {
                 source  => %{$user_data}{source}."",
                 dest    => %{$user_data}{dest}."",
                 ack     => 1,
                 seq     => $synack->{acknum},
                 ack_seq => $synack->{seqnum} + 1,
                 data    => $payload
                },
        });
      $n->send;
      print "Sent ACK with data: \"$payload\"\n";
      pcap_breakloop($pcap);
    }
  }
}
