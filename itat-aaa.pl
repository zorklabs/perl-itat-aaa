#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
#
#  Copyright 2002  The FreeRADIUS server project
#  Copyright 2002  Boian Jordanov <bjordanov@orbitel.bg>
#

#
# Based on default rlm_perl example code
#
# You can use every module that comes with your perl distribution!
#
# If you are using DBI and do some queries to DB, please be sure to
# use the CLONE function to initialize the DBI connection to DB.
#

use strict;
use warnings;

# use ...
use Data::Dumper;
use Cache::Memcached;
use JSON;
use WWW::Mechanize;
use Data::UUID;
use Time::Piece;
use threads;
use threads::shared;

# Bring the global hashes into the package scope
our (%RAD_REQUEST, %RAD_REPLY, %RAD_CHECK, %RAD_STATE);

#
# This the remapping of return values
#
use constant {
    RLM_MODULE_REJECT   => 0, # immediately reject the request
    RLM_MODULE_OK       => 2, # the module is OK, continue
    RLM_MODULE_HANDLED  => 3, # the module handled the request, so stop
    RLM_MODULE_INVALID  => 4, # the module considers the request invalid
    RLM_MODULE_USERLOCK => 5, # reject the request (user is locked out)
    RLM_MODULE_NOTFOUND => 6, # user not found
    RLM_MODULE_NOOP     => 7, # module succeeded without doing anything
    RLM_MODULE_UPDATED  => 8, # OK (pairs modified)
    RLM_MODULE_NUMCODES => 9  # How many return codes there are
};

# Same as src/include/log.h
use constant {
    L_AUTH         => 2,  # Authentication message
    L_INFO         => 3,  # Informational message
    L_ERR          => 4,  # Error message
    L_WARN         => 5,  # Warning
    L_PROXY        => 6,  # Proxy messages
    L_ACCT         => 7,  # Accounting messages
    L_DBG          => 16, # Only displayed when debugging is enabled
    L_DBG_WARN     => 17, # Warning only displayed when debugging is enabled
    L_DBG_ERR      => 18, # Error only displayed when debugging is enabled
    L_DBG_WARN_REQ => 19, # Less severe warning only displayed when debugging is enabled
    L_DBG_ERR_REQ  => 20, # Less severe error only displayed when debugging is enabled
};

# Connection strings
my $MEMCACHED_HOST = "0.0.0.1:11211";
my $MEMCACHED_KEY = "radius_shaper_";
my $MEMCACHED_COUNTERS_KEY = "radius_shaper_counter_";
my $BILLING_CONN_STR = 'https://my-super-external-api/radiusAuthenticate?mac=';

# Runtime strings constants
my $USERNAME = 'username';
my $IPV4 = 'ip';
my $SPEED_FOREIGN = 'speed_world';
my $SPEED_REGIONAL = 'speed_regional';
my $STATE = 'state';
my $VLAN_ID = 'vlan_id';
my $SWITCH_MAC = 'switch_mac';
my $SWITCH_MODULE = 'switch_module';
my $SWITCH_PORT = 'switch_port';
my $ID_ACTIVE_PERIOD = 1;
my $SERVICE_LOCAL = 'svc-local-ipoe';
my $SERVICE_REGIONAL = 'svc-regional-ipoe';
my $SERVICE_FOREIGN = 'svc-global-ipoe';
my @SERVICE_REDIRECT = ('guest_redirect', 'access-denied');
my @SERVICE_NAT = ('fake_to_nat', 'nat44');
my $AUTH_RETRY_LIMIT = 5000;
my $BRAS2 = '0.0.0.2';

my $EXCEPT_USER_ABSENCE = "Doesn't exist";
my $EXCEPT_USER_BANNED = "Exceeded the maximum number of allowed requests";

# Function to handle authorize
sub authorize {
    # For debugging purposes only
#   &log_request_attributes;

    # Here's where your authorization code comes
    # You can call another function from here:
    # &test_call;

    return RLM_MODULE_OK;
}

# Function to handle authenticate
sub authenticate {
    # Create Request ID to separate logging information
    my $logID = create_reguest_id();
    
    &radiusd::radlog(L_INFO, "RID: $logID, User authentication start: $RAD_REQUEST{'User-Name'}");

    my $requested_user = $RAD_REQUEST{'User-Name'};
    my $bras_address = $RAD_REQUEST{'NAS-IP-Address'};

    &radiusd::radlog(L_INFO, "RID: $logID, BRAS IPv4 address: $bras_address");

    my %user_attributes;

    # User doesn't exist or banned if exception occured
    eval {
        %user_attributes = create_user($requested_user, $logID);
        1;
    }
    or do {
        if ($@ =~ $EXCEPT_USER_ABSENCE) {
            &radiusd::radlog(L_INFO, "RID: $logID, User doesn't exist: $RAD_REQUEST{'User-Name'}");
        }
        elsif ($@ =~ $EXCEPT_USER_BANNED) {
            &radiusd::radlog(L_INFO, "RID: $logID, User BANNED: $RAD_REQUEST{'User-Name'}");
        }
        return RLM_MODULE_REJECT;
    };

    $RAD_REPLY{'Framed-IP-Address'} = $user_attributes{$IPV4};
    $RAD_REPLY{'ERX-Service-Activate:3'}  = $SERVICE_LOCAL;
    $RAD_REPLY{'ERX-Service-Activate:4'}  = "$SERVICE_REGIONAL($user_attributes{$SPEED_REGIONAL})";
    $RAD_REPLY{'ERX-Service-Activate:5'}  = "$SERVICE_FOREIGN(".
                                              "$user_attributes{$SPEED_FOREIGN},".
                                              "$user_attributes{$SPEED_REGIONAL})";

    &radiusd::radlog(L_INFO, "RID: $logID, IPv4: $user_attributes{$IPV4}");
    &radiusd::radlog(L_INFO, "RID: $logID, Speed Regional: ".speed_in_mbit($user_attributes{$SPEED_REGIONAL}));
    &radiusd::radlog(L_INFO, "RID: $logID, Speed Foreign: ".speed_in_mbit($user_attributes{$SPEED_FOREIGN}));

    # Check state 1 ($ID_ACTIVE_PERIOD) - active period
    #             other - closed period
    if ($user_attributes{$STATE} != $ID_ACTIVE_PERIOD) {
        if ($bras_address eq $BRAS2) {
            $RAD_REPLY{'ERX-Service-Activate:6'}  = $SERVICE_REDIRECT[1];
        }
        else {
            $RAD_REPLY{'ERX-Service-Activate:6'}  = $SERVICE_REDIRECT[0];
        }
        # $RAD_REPLY{'ERX-Service-Activate:6'}  = $SERVICE_REDIRECT;
        $RAD_REPLY{'ERX-Service-Statistics:6'} = '0';

        &radiusd::radlog(L_INFO, "RID: $logID, Period is CLOSED with $SERVICE_REDIRECT[1]");
    }
    
    # Check IP is private. If Yes add redirection to nat servers
    if ($user_attributes{$IPV4} =~ /^10\./) {
        if ($bras_address eq $BRAS2) {
            $RAD_REPLY{'ERX-Service-Activate:7'} = $SERVICE_NAT[1];
        }
        else {
            $RAD_REPLY{'ERX-Service-Activate:7'} = $SERVICE_NAT[0];
        }
        $RAD_REPLY{'ERX-Service-Statistics:7'} = '0';
    }

    &radiusd::radlog(L_INFO, "RID: $logID, User successfully authenticated: $RAD_REQUEST{'User-Name'}");

    return RLM_MODULE_OK;
}

# Custom code goes from here
# Init Memcached server
sub init_memcached {
    my ($hostname) = @_;

    my $memcached = new Cache::Memcached {'servers' => [$hostname],
                                          'debug' => 0,
                                         };

    $memcached->set_compress_threshold(10_000);
    $memcached->enable_compress(0);

    $memcached;
}
 
# Request Memcached first
sub request_memcached {
    my ($memcached,
        $username) = @_;

    # $memcached->delete("$MEMCACHED_KEY$username");

    # Check fail2ban first
    my $fail_counter = $memcached->get("$MEMCACHED_COUNTERS_KEY$username");

    if($fail_counter && $fail_counter>$AUTH_RETRY_LIMIT)
    {
        # Stop further processing
        die($EXCEPT_USER_BANNED);
    }

    my $attributes = $memcached->get("$MEMCACHED_KEY$username");

    if($attributes) {
        my $decoder = JSON->new->allow_nonref;
        $attributes = $decoder->decode($attributes);
    }
    
    $attributes
}

# Perform secondary request to billing
sub request_billing {
    my ($conn_str, $username) = @_;
    my $url = "$conn_str$username";
    my $attributes;

    my $billing = WWW::Mechanize->new('autocheck' => 0);
    $billing->get($url);

    if ($billing->success() && length $billing->content) {
        my $decoder = JSON->new->allow_nonref;
        $attributes = $decoder->decode($billing->content);
    }

    $attributes;
}

# Request Acces for user
sub request_user_access {
    my ($username, $logID) = @_;
    my $memcached = init_memcached($MEMCACHED_HOST);
    my $cached_user_attributes = request_memcached($memcached,
                                                   $username);
    my $user_attributes;

    if ($cached_user_attributes) {
        $user_attributes = $cached_user_attributes;
        &radiusd::radlog(L_INFO, "RID: $logID, Retrieved from Memcached");
    }
    else {
        my $billing_user_attributes = request_billing($BILLING_CONN_STR,
                                                      $username);
        if ($billing_user_attributes) {
            $user_attributes = $billing_user_attributes;
 
            # Update deadtimer to Memcached
            $memcached->set("$MEMCACHED_KEY$username",
                            encode_json $user_attributes,
                            86400);
            &radiusd::radlog(L_INFO, "RID: $logID, Retrieved from Billing");
        }
        else {
            die($EXCEPT_USER_ABSENCE);
        }
    }

    $user_attributes;
}

sub create_user {
    my ($username, $logID) = @_;
    my $user_attributes = request_user_access($username, $logID);
    my %client_params;
    
    if ($user_attributes) {
        %client_params = %$user_attributes;
    }

    %client_params;
}

# Per process ID for prepending logging information
sub create_reguest_id {
    my $ug = Data::UUID->new;
    my $uuid1 = $ug->to_string($ug->create());

    my @parts = split /-/, $uuid1;
    
    $parts[0];
}

# Return speed string to print in logs
sub speed_in_mbit {
    my ($value) = @_;
    my $converted_size = ($value/(1000000));

    return $converted_size."Mb";
}

my @buffer :shared;
my $BUFFER_LENGTH = 40000;

# Function to handle accounting
sub accounting {
    # Warning: Make shure that 
    # update control {
    #     &Tmp-Integer-0 := "%{integer: request:Event-Timestamp}"
    # }
    # stranza is exists before perl module activation in accounting section
    
    &radiusd::radlog(L_INFO, "RID: Accounting, Corrected timestamp: $RAD_CHECK{'Tmp-Integer-0'}");

    return RLM_MODULE_OK;
}

sub accounting_shaded {
    my @buffer_data = ();

    # if (exists $RAD_REQUEST{'Acct-Output-Packets'} && exists $RAD_REQUEST{'ERX-Service-Session'} ) {
    # if (exists $RAD_REQUEST{'Acct-Output-Packets'}) {
    if (exists $RAD_REQUEST{'ERX-Service-Session'}) {
        {
           lock @buffer;

            if (scalar(@buffer) > $BUFFER_LENGTH) {
                &radiusd::radlog(L_INFO, "RID: Accounting, Maximum buffer size reached perfoming drain and insert to DB.");
                    @buffer_data = @buffer;

                    @buffer = ();

                    &radiusd::radlog(L_INFO, "RID: Accounting, Buffer cleared.");
                    # &radiusd::radlog(L_INFO, "RID: Accounting, Buffer copy size is ".scalar(@buffer_data)." elements.");
                    # &radiusd::radlog(L_INFO, "RID: Accounting, Buffer size is ".scalar(@buffer)." elements.");
                }

            my $str = "$RAD_REQUEST{'User-Name'}%$RAD_REQUEST{'Acct-Session-Id'}%$RAD_REQUEST{'Event-Timestamp'}%$RAD_REQUEST{'Acct-Input-Octets'}%$RAD_REQUEST{'Acct-Output-Octets'}%$RAD_REQUEST{'ERX-Service-Session'}%$RAD_REQUEST{'Framed-IP-Address'}";

            push @buffer, $str;

            #&radiusd::radlog(L_INFO, "RID: Accounting, Custom time: %$RAD_REQUEST{'Event-Timestamp-Integer-0'}");
        }

        if (scalar(@buffer_data) >= $BUFFER_LENGTH) {
            &radiusd::radlog(L_INFO, "RID: Accounting, Buffer size (".scalar(@buffer_data).") is more or equal ".$BUFFER_LENGTH.". Perfoming drain.");
            drain(@buffer_data);
        }

     &radiusd::radlog(L_INFO, "RID: Accounting, Buffer size is ".scalar(@buffer)." elements.");
    }

    return RLM_MODULE_OK;
}

# Prepare values for DB
sub convert_buffer_to_values {
    my (@buffer) = @_;
    
    my $value_string = "";

    for(@buffer){
        my @data = split /%/, $_;
        $value_string = $value_string."('$data[0]','$data[1]','". convert_timestamp_format($data[2])."',$data[3],$data[4],'$data[5]','$data[6]'),";
    }
    
    chop($value_string);

    $value_string;

}

# Convert default timestamp to DB insertable format
sub convert_timestamp_format {
    my ($timestamp) = @_;

    $timestamp =~ s/ EEST//;
    my $time = Time::Piece->strptime($timestamp, '%b %d %Y %T');

    $time->date." ".$time->time;
}


# Write buffer to DB
sub drain {
    my (@buffer_copy) = @_;

    my $url = 'http://clickhouse-host:8123/';
    my $chdb = WWW::Mechanize->new('autocheck' => 0);

    my $val = convert_buffer_to_values(@buffer_copy);
    $chdb->post($url, content=>"INSERT INTO accounting.tabbex VALUES $val");

    # &radiusd::radlog(L_INFO, "RID: Accounting, Drain: INSERT INTO accounting.tabbex VALUES $val");
    # &radiusd::radlog(L_INFO, "RID: Accounting, Drain: ".scalar(@buffer_copy)."");
}
