#!perl
use strict;
use warnings;
use Config::Simple;
use Tk;
use Tk::HList;
use Tk::FileEntry;
use Tk::StatusBar;
use Tk::ItemStyle;
use Tk::HdrResizeButton;
use Tk::JComboBox;
use Net::RawIP;
use NetAddr::IP;
use Net::Pcap;
use LWP::Simple;

use URI::Normalize qw( normalize_uri );

use IO::Socket::INET;
use Socket;
use Sys::Hostname qw(hostname);
use Net::PcapUtils;
use NetPacket::Ethernet qw(:strip);
use NetPacket::IP qw(:strip);
use NetPacket::TCP;

use POSIX qw(strftime);
use Time::HiRes qw(gettimeofday);
use Time::Piece;

use constant COMM_PORT => 7777;

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
  while(1)
  {
      # wait for new client connection
      my $client_socket = $socket->accept();

      # get information about the client
      my $client_address = $client_socket->peerhost();
      my $client_port = $client_socket->peerport();
      print "connection from $client_address:$client_port\n";

      my $data = "";
      my $data2;
      $client_socket->recv($data, 1024);
      if ($data =~ /;/) # two requests
      {
        my @d = split(/;/, $data);
        $data = $d[0];
        $data2 = $d[1];
      }
      if ( $data =~ /^[0-9,.E]+$/ ) # check if number
      {
        print "received request to bind port $data\n";
        my $tmp_socket = new IO::Socket::INET (
            LocalHost => $config{"TARGET_IP"},
            LocalPort => $data,
            Proto => 'tcp',
            Listen => 5,
            Reuse => 1
        );
        die "cannot create socket $!\n" unless $tmp_socket;
        print "port $data is open, waiting for client.\n";

        $client_socket->send("OK"); # let sender know the port is open, or send payload
        shutdown($tmp_socket, 1);

        my $tmp_client = $tmp_socket->accept();
        $tmp_client->send($data2) if ($data2);

        # handshake is done -> close socket
        print "Handshake complete, closing port $data.\n";
        shutdown($tmp_client, 1);
        $tmp_socket->close();
      }
      elsif ( $data =~ /from_server/)
      {
        my @spl = split(/:/, $data);
        print "received FROM_SERVER request: \"$data\". Sending \"".$spl[1]."\" back.\n";
        $client_socket->send($spl[1]);
      }
      else
      {
        $client_socket->send("0"); # receiver interprets this as error
        print "received incorrect data: $data\n";
        shutdown($client_socket, 1);
      }
  }

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
      if ($dst ne "any" && $dst !~ /\$/)
      {
        # Snort may not detect the packet if it's being sent to non-existent hosts,
        # or if the TARGET_IP is not in the subnet of the destination.
        $dst = (split(/\//, $dst))[0] if ($dst =~ /\//);
        $dst =~ s/\[//g;
        $dst = NetAddr::IP->new($dst);
        my $tgt = NetAddr::IP->new($config{"TARGET_IP"});
        if (!$tgt->within($dst))
        {
            # we don't just skip here, because data like flowbits should still be stored in the background
            $dontadd = 1;
        }
      }

      my ($options) = $row =~ /\((.*?)\)/; # extract options part in brackets
      $options =~ s/\"//g;                 # remove " from string
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
            $hlist->itemCreate($item_counter, 8, -text => "" . $optionlist{$k});
            last;
          }
        }
      }
      $additional_data{$item_counter} = \%optionlist;

      $item_counter++;
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
      fire(\@r);
    }
  }

  sub flood()
  {
    # we syn flood first and then mix some random attacks in

    my $ip = $config{"TARGET_IP"};
    my $port = int(rand(65534) + 1);
    my $size = 1024;
    my $time = 5; # flood for 5 secinds

    my $iaddr = inet_aton("$ip") or die "Cannot resolve hostname $ip\n";
    my $endtime = time() + ($time ? $time : 1000000);

    socket("flood", PF_INET, SOCK_DGRAM, 17);
# disabled for faster debugging
  #  for (;time() <= $endtime;) {
  #    my $psize = $size ? $size : int(rand(1024-64)+64) ;
  #    my $pport = $port ? $port : int(rand(65500))+1;
  #    send("flood", pack("a$psize","flood"), 0, pack_sockaddr_in($pport, $iaddr));
  #  }

    $endtime = time() + ($time ? $time : 1000000);
    my $atcks = 0;
    # now keep flooding but also send "attacks"
    for (;time() <= $endtime;) {
      my $psize = $size ? $size : int(rand(1024-64)+64) ;
      my $pport = $port ? $port : int(rand(65500))+1;
      send("flood", pack("a$psize","flood"), 0, pack_sockaddr_in($pport, $iaddr));
      if (int(rand(3)) == 0) # 33% chance
      {
          my $row = int(rand($item_counter));
          my @r;
          foreach my $col (0 .. $hlist->cget(-columns) - 1)
          {
            push @r, $hlist->itemCget($row, $col, '-text');
          }
          $atcks++;
          fire(\@r);
      }
    }
  }

  sub benchmark()
  {
    my $time = 60;
    my $endtime = time() + ($time ? $time : 1000000);
    # fires all attacks in the list sequentially
    for (;time() <= $endtime;)
    {
      for (my $i=0; $i<$item_counter; $i++)
      {
        my @r;
        foreach my $col (0 .. $hlist->cget(-columns) - 1)
        {
          push @r, $hlist->itemCget($i, $col, '-text');
        }
        fire(\@r);
      }
    }
    print "Benchmark done.\n";
  }

  sub fire()
  {
    my @infos = @{$_[0]};

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

    if ($src_ip eq "any")
    {
      $src_ip = "169.254.222.155"; # TODO: GET LOCAL IP FROM SOCKET
      #$src_ip =  int(rand(256)) . "." . int(rand(256)) . "." . int(rand(256)) . "." . int(rand(256));
    }

    # Remove CIDR notation if existing
    $src_ip = (split(/\//, $src_ip))[0] if ($src_ip =~ /\//);
    $dst_ip = (split(/\//, $dst_ip))[0] if ($dst_ip =~ /\//);

    # Set the destination to TARGET_IP, which is no problem if the destination is "any".
    # Otherwise, the user has been warned.
    $dst_ip = $config{"TARGET_IP"};

    $src_port = int(rand(65535)) + 1 if ($src_port eq "any");
    $src_port =~ s/\:.*//;
    print "srcport: $src_port\n";

    # Set destination port to COMM_PORT if we can, so we don't have to request
    # the receiver to bind a second port if a handshake was required
    $dst_port = COMM_PORT if ($dst_port eq "any");
    $dst_port =~ s/\:.*//;
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

    foreach my $key ( sort { (split(/:/, $a))[0] <=> (split(/:/, $b))[0] } keys %{ $additional_data{$id} })
    {
      print "PARSING $key #######################\n\n";
      my $add_data = $additional_data{$id}{$key};

      # CONTENT
      if ($key =~ /:content/)
      {
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
          print "Payload \"".$add_data."\" has no hex data.\n";
          # This is a weird workaround, but for some reason rawIP does not accept $add_data
          # it works if the value of $add_data was given directly ($proto{data} .= "XYZ")
          # I try to achieve this by converting the chars to hex and back
          my @ws = split(//, $add_data);
          foreach my $ascii (@ws)
          {
            my $hex_string = unpack "H*", $ascii;
               $hex_string = chr(hex $hex_string);
            # Translate hex
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
      elsif ($key =~ /:uricontent/)
      {
        $payload .= normalize_uri($add_data);
        $length_last_content = length(normalize_uri($add_data));
        $doe .= $length_last_content;
        $is_uri = 1;
      }
      elsif ($key =~ /offset/)
      {
        print "offset key: $key\n";
        print "offset: $add_data\n";
        print "payload: $payload\n";
        print "doe: $doe\n";

        if ($add_data < $doe) # content should be placed in earlier part of payload
        {
          my $last_content = substr($payload, $doe-$length_last_content, $length_last_content, "");
          substr($payload, $add_data, $length_last_content, $last_content);
        }
        else
        {
          #if our content has byte_test data added, this counts aswell
          my $diff = $add_data + $length_last_content - $doe;
          print "diff: $diff\n";
          substr($payload, $length_last_content, 0, 'x' x $diff) if ($diff > 0);
          print "new content: $payload\n";
        }
        $doe = $add_data;
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
        my $type = (split (/ /, $spl[0]))[1];
        my $count =  (split (/ /, $spl[2]))[1];
        $repeat = $count if ($type =~ /threshold/ || $type =~ /both/);
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
        # Flags are 3 bits wide and the offset 13 bits -> 16 bits total
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
         if ($add_data =~ /<>/)
         {
           $payload .= "x" x (split(/<>/, $add_data))[1];
         }
         elsif ($add_data =~ /</)
         {
           $payload .= "x" x ((split(/</, $add_data))[1] - 1);
         }
         elsif ($add_data =~ />/)
         {
           $payload .= "x" x ((split(/>/, $add_data))[1] + 1);
         }
      }
      elsif ($key =~ /:window/)
      {
          my $win = $add_data;
          if ($add_data =~ /!/)
          {
            $win = (split (/!/, $add_data))[1];
            if ($win == "20")
            {
              $win = 10;
            }
            else
            {
              $win = 20;
            }
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
      # MESSAGE
      elsif ($key =~ /:msg/)
      {
        # irrelevant to payload
        next;
      }
      else
      {
        print "[WARNING] Rule option \"$key\" is not supported.\n";
      }
    }

    $proto{data} = $payload;

    for (my $i = 0; $i < $repeat; $i++)
    {
      if ($protocol eq "tcp" || $protocol eq "ip")
      {
          if ($is_uri)
          {
            # for this to work, a webserver like apache2 must be running on the target system
            # we shortcut creating a http request ourselves by just using the built in module
            my $request = "http://".$config{"TARGET_IP"}.$payload;
            get $request;
            next;
          }

          $rawIP_tcp->set({
            %ip,
            tcp => { %proto }
          });

          print "Target is: ".$ip{ip}{saddr}.":".$proto{source}."\n";
          if (!$handshake && !$from_server)
          {
            $rawIP_tcp->send;
            print "Sent TCP packet.\n";
          }
          else
          {
            print "Requiring handshake.\n";
            tcp_handshake($rawIP_tcp, $from_server);
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

  sub tcp_handshake
  {
    my $raw_tcp = shift;
    my $from_server = shift;

    my %ipinfos = %{$raw_tcp->get({ip => [qw(saddr)]})};
    my %tcpinfos = %{$raw_tcp->get({tcp => [qw(source dest data)]})};

    my $src_host = inet_ntoa(pack("N",shift||$ipinfos{saddr}));
       $src_host = (gethostbyname($src_host))[4];

    my $src_port = $tcpinfos{source};
    my $dst_port = $tcpinfos{dest};

    if ($from_server)
    {
      # switch source and dest ports
      my $tmp = $src_port;
      $src_port = $dst_port;
      $dst_port = $tmp;
    }

    if ($dst_port ne "".COMM_PORT)
    {
      my $val = $dst_port;
      $val .= ";".$tcpinfos{data} if ($from_server);
      request_open_port($val);
    }

    my $err = '';
    $pcap = pcap_open_live("eth0", 1024, 0, 0, \$err)
            or die "Can't open device eth0: $err\n";

    # Destination address has to be TARGET_IP, or handshake won't work
    my $dst_host = $config{"TARGET_IP"};
       $dst_host = (gethostbyname($dst_host))[4];

    my ($sock);
    socket($sock, AF_INET, SOCK_STREAM, getprotobyname('tcp')) || die $!;
    bind($sock, pack_sockaddr_in($src_port, $src_host));
    my $paddr = sockaddr_in($dst_port, $dst_host);
    connect($sock, $paddr) or die "connection failed: $!";

    if (!$from_server)
    {
      pcap_loop($pcap, -1, \&process_packet, $tcpinfos{data});
      pcap_close($pcap);
    }

    $sock->close();

  }

  sub process_packet
  {
    my ($user_data, $header, $packet) = @_;
    # Note: we should probably make sure that the syn-ack is actually sent from our target
    my $synack_eth 	= NetPacket::Ethernet->decode($packet);
    my $sa_ip  	= NetPacket::IP->decode($synack_eth->{data});
    my $synack = NetPacket::TCP->decode($sa_ip->{data});

    if ($synack->{flags} eq "18") # SYN-ACK
    {
      print "Got SYN-ACK from ". $sa_ip->{src_ip}."\n";
      print "Sequence Number: ".$synack->{seqnum}."\n";
      print "Arrived at ".$sa_ip->{dest_ip}.":". $synack->{dest_port}."\n";
      print "Target: ".$sa_ip->{src_ip}.":".$synack->{src_port}."\n";
      print "Payload: $user_data\n";

      my $n = Net::RawIP->new({
         ip  => {
                 saddr => $sa_ip->{dest_ip},
                 daddr => $sa_ip->{src_ip},
                },
         tcp => {
                 source  => $synack->{dest_port},
                 dest    => $synack->{src_port},
                 ack     => 1,
                 seq     => $synack->{acknum},
                 ack_seq => $synack->{seqnum} + 1,
                 data    => $user_data
                },
        });
      $n->send;
      print "Sent ACK with data: \"$user_data\"\n";
      pcap_breakloop($pcap);
    }
  }

  sub request_open_port
  {
    my $port = shift;
    my $payload = shift;

    my $socket = new IO::Socket::INET (
      PeerHost => $config{"TARGET_IP"},
      PeerPort => COMM_PORT,
      Proto => 'tcp',
    );
    die "cannot connect to the server $!\n" unless $socket;
    print "connected to the server\n";

    $port = "$port;$payload" if ($payload);
    print "sent port request $port\n";
    $socket->send($port); # send request to open port and payload if given
    shutdown($socket, 1);

    my $response = "";
    $socket->recv($response, 1024);
    print "Requested open port: $response\n";

    $socket->close();
  }
}
