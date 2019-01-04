cli script tmpl_export {
proc load_profile {p_typ list} {

upvar $list profs
#tmsh::cd /AS3demo2/DemoApplication
#foreach partition [tmsh::get_config /sys folder] {
#    tmsh::cd /$partition
#    puts "Partition:  $partition"

foreach typ $p_typ {
    foreach profile [tmsh::get_config /ltm profile $typ] {
        set profile_name [tmsh::get_name $profile]
        set profile_type [string range [tmsh::get_type $profile] 12 end]
        #puts "$profile_name $profile_type"
        set profs($profile_name) $profile_type
    }
}
#}
}


proc load_WAF_pol {list} {

    upvar $list waf_pols
    foreach pol [tmsh::get_config /asm policy]  {
        set pol_name [tmsh::get_name $pol]
        foreach virt [tmsh::get_field_value [lindex [tmsh::get_config /asm policy $pol_name virtual-servers] 0] virtual-servers] {
            set waf_pols($virt) $pol_name
        }

    }

}


proc load_pool {pool_name decl} {

    upvar $decl pool_JSON
    set pool [lindex [tmsh::get_config /ltm pool $pool_name all-properties] 0]
    set monitor [string trimright [tmsh::get_field_value $pool monitor]]
    set retries [tmsh::get_field_value $pool reselect-tries]
    set lb_method [tmsh::get_field_value $pool load-balancing-mode]
    set action  [tmsh::get_field_value $pool service-down-action]
    set members [tmsh::get_field_value $pool members]
   # puts "$pool_name $monitor $retries $lb_method $action"

    set addresses ""
    set port "80"
    get_addr_port [tmsh::get_name [lindex $members 0]] ip port
    foreach mbr $members {
        set addresses $addresses"[tmsh::get_field_value $mbr address]",
    }
    set addresses [string trimright $addresses ,]
    set list_of_changes [list POOL_NAME_HERE $pool_name MONITOR_HERE $monitor RETRIES_HERE $retries LB_MODE_HERE $lb_method ACTION_DOWN_HERE $action SERVER_ADDRESSES_HERE $addresses PORT_HERE $port]

    set pool_JSON [string map $list_of_changes $::pool_decl]


}



proc get_addr_port {s ip prt} {

    upvar $ip IP $prt port
    regexp {(((\S+)\/)*)(\S+):(\S+)} $s foobar foobar foobar partition IP port

    #puts "--- $partition $IP $port"

    switch $port {
        https { set port "443" }
        http { set port "80" }
        ftp { set port "21" }
        ssh { set port "22" }
        telnet { set port "23" }
    }

}






proc script::run {} {


load_profile {tcp client-ssl server-ssl http web-security} profiles
load_WAF_pol waf_pol

set AS3_host "BigIP"
if {$tmsh::argc >0 } {
    set virtual_to_export [lindex $tmsh::argv 1]
    puts "Exporting: [lindex $tmsh::argv 1] "
} else {
    set virtual_to_export ""
}



foreach virt [tmsh::get_config /ltm virtual $virtual_to_export all-properties] {
    set systemTime [clock seconds]
    set id [clock format $systemTime -format %m-%d-%Y_%H:%M:%S]


    set virt_name [tmsh::get_name $virt]
    set virt_dest_IP [tmsh::get_field_value $virt "destination"]
    puts "\n[tmsh::get_name $virt]   $virt_dest_IP\n"

    set IP ""
    set port ""
    get_addr_port $virt_dest_IP IP port

    regexp {(\S+)\/(\S+)}  [tmsh::get_name [lindex [tmsh::get_config /sys management-ip] 0]] foobar mgmt_IP mask
    set partition [tmsh::get_field_value $virt "partition"]
    set list_of_changes [list "VIRTUAL_NAME_HERE" $virt_name]
    lappend list_of_changes "DESTINATION_IP_HERE" $IP
    lappend list_of_changes "MANAGEMENT_IP_HERE" $mgmt_IP

    # Add pool name
    set pool_name  "[tmsh::get_field_value $virt pool]"
    lappend list_of_changes "POOL_NAME_HERE" $pool_name
    set pool_JSON ""
    load_pool $pool_name pool_JSON

    lappend list_of_changes "ID_HERE" $id
    lappend list_of_changes "DESCRIPTION_HERE"  "$virt_name - [string map {\" " "} [tmsh::get_field_value $virt description]]"
    lappend list_of_changes "PORT_HERE" $port

    foreach virt_profile [tmsh::get_field_value [lindex [tmsh::get_config /ltm virtual $virt_name profiles] 0] profiles] {
#        puts  "[tmsh::get_name $virt_profile]   TYPE $profiles([tmsh::get_name $virt_profile])"

        if { [catch { set profil_type $profiles([tmsh::get_name $virt_profile]) } ] } {
            set string ""
            set profil_type ""
        }
        set profil_name "/$partition/[tmsh::get_name $virt_profile]"
        switch $profil_type {
            tcp  { set string "TCP_PROFILE_HERE"
                switch  [tmsh::get_field_value $virt_profile context] {
                    clientside { set string "CLIENTSIDE_TCP_PROFILE_HERE" }
                    serverside { set string "SERVERSIDE_TCP_PROFILE_HERE" }
                    all { lappend list_of_changes SERVERSIDE_TCP_PROFILE_HERE "wan"
                          set string "CLIENTSIDE_TCP_PROFILE_HERE"
                    }
                }
            }
            http { set string "HTTP_PROFILE_HERE"
                foreach feature [tmsh::get_config /ltm profile $profil_type $profil_name non-default-properties]  {
    #                puts "$feature"
                }
            }
            client-ssl { set string "CLIENT_SSL_PROFILE_HERE" }
            server-ssl { set string "SERVER_SSL_PROFILE_HERE" }
            web-security { set string "LTM_POLICY_HERE" }
            default { set string "WAF_POLICY_HERE"
                        set profil_name "/Common/$waf_pol($virt_name)"
            }
        }
        lappend list_of_changes $string $profil_name

    }

    #puts $list_of_changes


    set new_declaration [string trimright [string map $list_of_changes $::declaration] \}\}\}\}]
    #puts $new_declaration,$pool_JSON\}\}\}\}
    puts "--------------------------------------------------------------------------"

    set logpol_out  [tmsh::get_field_value $virt security-log-profiles]
    if { $logpol_out ne "" } {
        set logpol_out /Common/[string map {\" ""} $logpol_out]
        set l [list "LOG_POLICY_HERE" $logpol_out]
        set logpol_out [string map $l $::log_pol]
        set logpol_out ,\n$logpol_out
    }

    set wafpol_out ""
    if { $waf_pol($virt_name) ne "" } {
        set l [list WAF_POLICY_HERE /Common/$waf_pol($virt_name)]
        set wafpol_out ,\n[string map $l  $::WAF_pol]
    }
    puts [string trimright $new_declaration \}]$wafpol_out$logpol_out\},\n$pool_JSON\n\}\n\}\n\}\n\}

    puts "--------------------------------------------------------------------------"


}

tmsh::cd /Common


}



proc script::init {} {

    set ::declaration {{
    "class": "AS3",
    "action": "deploy",
    "persist": true,
    "declaration": {
        "class": "ADC",
        "schemaVersion": "3.2.0",
        "id": "Export_Date:_ID_HERE",
        "target": {
           "hostname": "MANAGEMENT_IP_HERE" },
        "AS3_Exports": {
            "class": "Tenant",
            "defaultRouteDomain": 0,
            "VIRTUAL_NAME_HERE": {
                "class": "Application",
                "template": "https",
                "serviceMain": {
                    "class": "Service_HTTPS",
                    "remark": "DESCRIPTION_HERE",
                    "virtualPort": PORT_HERE,
                    "clientTLS": {
                       "bigip": "SERVER_SSL_PROFILE_HERE"
                    },
                    "serverTLS": {
                       "bigip": "CLIENT_SSL_PROFILE_HERE"
                    },
                    "virtualAddresses": ["DESTINATION_IP_HERE"],
                    "redirect80": false,
                    "pool":  "POOL_NAME_HERE",
                    "profileTCP": {
                                "egress": "SERVERSIDE_TCP_PROFILE_HERE",
                                "ingress": { "bigip": "CLIENTSIDE_TCP_PROFILE_HERE" }
                    },
                    "profileHTTP": { "bigip": "HTTP_PROFILE_HERE" },
                   "persistenceMethods": [] }}}}}}


    set ::pool_decl {                     "POOL_NAME_HERE": { "class": "Pool", "monitors": [ "MONITOR_HERE"  ],
                "reselectTries": RETRIES_HERE, "loadBalancingMode": "LB_MODE_HERE",
                "serviceDownAction": "ACTION_DOWN_HERE",
                    "members": [{
                            "servicePort": PORT_HERE,
                            "serverAddresses": [ SERVER_ADDRESSES_HERE ] }  ]
                    }
                }




    set ::WAF_pol {                    "policyWAF": {
                       "bigip": "WAF_POLICY_HERE"
                    }
                    }


    set ::log_pol {                    "securityLogProfiles": [{ "bigip":"LOG_POLICY_HERE"}]}


 #   puts [string trimright $::declaration \}\}\}\}\}],\n$::WAF_pol\},\n$::log_pol\n\}\}\}\}


}
    
}

