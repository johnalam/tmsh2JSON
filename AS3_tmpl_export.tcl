
cli script tmpl_export {
proc load_profile {p_typ list} {

upvar $list profs

foreach typ $p_typ {
    foreach profile [tmsh::get_config /ltm profile $typ] {
        set profile_name [tmsh::get_name $profile]
        set profile_type [string range [tmsh::get_type $profile] 12 end]
        #puts "--> $profile_name $profile_type"
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
    if { $monitor eq "none" } { set monitor "tcp" }
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

    set pool_JSON "$pool_JSON,\n[string map $list_of_changes $::pool_decl]"

    return pool_JSON
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


proc get_irule_json {rule json ptr} {  
    set rule [regsub -all -line {\n}  $rule "\\n"]

    regexp {^ltm rule (\S+) \{(.*)\}} $rule p0 rulename irulebody
    set irulebody [regsub -all -line {\"}  $irulebody {\"} ]

#    puts $irulebody
    set rule_json "$json,\n$::white_spaces\"$rulename\": \{\n$::white_spaces       \"class\":\"iRule\",\n$::white_spaces       \"iRule\":\"$irulebody\",\n$::white_spaces       \"expand\": true\n$::white_spaces\}"
    set rule_pointer "$ptr  \"$rulename\","
    return [list $rule_json $rule_pointer]

}



proc script::run {} {


load_profile {tcp fastl4 client-ssl server-ssl http web-security} profiles
load_WAF_pol waf_pol

set AS3_host "BigIP"
if {$tmsh::argc >0 } {
    set cmd1 [string trimleft [lindex $tmsh::argv 1] '-']
    switch $cmd1 {
        k { 
            set keyword [lindex $tmsh::argv 2]
            set virtual_to_export ""
            set application_name "Application1"
            set tenant_name "Tenant1"
            puts "Exporting virtuals using keyword $keyword"
        }
        default {
            set virtual_to_export [lindex $tmsh::argv 1]
            puts "Exporting: [lindex $tmsh::argv 1] "
        }
    }
} else {
    set virtual_to_export ""
}

set tenant_name "Tenant1"

regexp {(\S+)\/(\S+)}  [tmsh::get_name [lindex [tmsh::get_config /sys management-ip] 0]] foobar mgmt_IP mask
set systemTime [clock seconds]
set id [clock format $systemTime -format %m-%d-%Y_%H:%M:%S]

set AS3_class_changes [list "ID_HERE" $id "MANAGEMENT_IP_HERE" $mgmt_IP] 


foreach virt [tmsh::get_config /ltm virtual $virtual_to_export all-properties] {
  set snatpoolJSON "" 
  #if \{ \[catch \{
    set virt_name [tmsh::get_name $virt]
    set virt_dest_IP [tmsh::get_field_value $virt "destination"]
    set description [tmsh::get_field_value $virt description]

    set kw_srch $virt_name$virt_dest_IP$description
    puts "\n[tmsh::get_name $virt]   $virt_dest_IP $description\n"


    if { ([info exists keyword] && [string first $keyword $kw_srch]<0) } {
        puts  "[string first $keyword $kw_srch] $kw_srch $keyword"
        continue
    }


    set snat_ptr ",\n$::white_spaces\"snat\" : "
    set snat_type [tmsh::get_field_value $virt "source-address-translation.type"]
    switch $snat_type {
        automap {
              append snat_ptr "\"auto\""
              set snat_type "auto" }
        none {
              append snat_ptr "\"none\""
             }
        snat { 
            set snat_pool [tmsh::get_field_value $virt "source-address-translation.pool"]
            append snat_ptr "\{\"use\": \"$snat_pool\"\}"
            set snat_type $snat_pool
            set snat_pool_cfg [lindex [tmsh::get_config /ltm snatpool $snat_pool members] 0]
            set snat_pool_members [tmsh::get_field_value $snat_pool_cfg "members"]
            set snatpoolJSON ",\n$::white_spaces     \"snatAddresses\" : \["
            foreach mbr $snat_pool_members {
                set snatpoolJSON "$snatpoolJSON \"$mbr\" ,"
            }
            set snatpoolJSON "[string trimright $snatpoolJSON ,]\]"
            set snatpoolJSON ",\n$::white_spaces\"$snat_pool\" : \{\n$::white_spaces     \"class\" : \"SNAT_Pool\"$snatpoolJSON\n$::white_spaces\}"
            #puts $snatpoolJSON
        }
    }

    set IP ""
    set port ""
    get_addr_port $virt_dest_IP IP port

    set partition [tmsh::get_field_value $virt "partition"]
    set list_of_changes [list "VIRTUAL_NAME_HERE" $virt_name]
    set app_class_changes [list "TENANT_NAME_HERE" $tenant_name]

    lappend list_of_changes "DESTINATION_IP_HERE" $IP
    lappend list_of_changes "MANAGEMENT_IP_HERE" $mgmt_IP
    #lappend list_of_changes "SNAT_TYPE_HERE" $snat_type


    # Add pool name
    set pool_name  "[tmsh::get_field_value $virt pool]"
    set pool_JSON ""
    if { $pool_name ne "none" } {
        lappend list_of_changes "POOL_NAME_HERE" $pool_name
        load_pool $pool_name pool_JSON
    }

    lappend list_of_changes "ID_HERE" $id
    lappend list_of_changes "DESCRIPTION_HERE"  "$virt_name - [string map {\" " "} [tmsh::get_field_value $virt description]]"
    lappend list_of_changes "PORT_HERE" $port

    set irule_json ""
    set irule_ptr ",\n                   \"iRules\": \["
    set rules [tmsh::get_field_value $virt "rules"]
    if { $rules ne "none" } {
        foreach irule $rules {
            set irule [lindex [tmsh::get_config ltm rule $irule] 0]
            set i 0
            foreach item [regexp -all -inline { pool (\S+)} $irule] {
                if { $i == 1 } {
                    load_pool $item pool_JSON
                    puts $item
                    set i 0
                } else {
                     set i 1
                }
            }

            set irule  [get_irule_json $irule $irule_json $irule_ptr]
            set irule_ptr  [lindex $irule 1]
            set irule_json [lindex $irule 0]

            #puts "\n----\n$irule_json"
       }
    }
    set irule_ptr [string trimright $irule_ptr ,]
    set irule_ptr "$irule_ptr\]"

    set wafpol_out ""
    set cltTLS_JSON ""
    set srvTLS_JSON ""


    foreach virt_profile [tmsh::get_field_value [lindex [tmsh::get_config /ltm virtual $virt_name profiles] 0] profiles] {
        set string ""
        set profil_type ""

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
            fastl4 {}
            http { set string "HTTP_PROFILE_HERE"
                foreach feature [tmsh::get_config /ltm profile $profil_type $profil_name non-default-properties]  {
    #                puts "$feature"
                }
            }
            client-ssl { 
                set l [list CLIENT_SSL_PROFILE_HERE $profil_name] 
                set cltTLS_JSON ,\n[string map $l $::cltTLS]
                }
            server-ssl {
                set l [list SERVER_SSL_PROFILE_HERE $profil_name] 
                set srvTLS_JSON ,\n[string map $l $::srvTLS]
                }
            web-security { set string "LTM_POLICY_HERE" }
            default {
                set string "xxx"
                if { [info exists waf_pol($virt_name)] } {
                     set string "WAF_POLICY_HERE"
                     set profil_name "/Common/$waf_pol($virt_name)"
                     if { $waf_pol($virt_name) ne "" } {
                        set l [list WAF_POLICY_HERE /Common/$waf_pol($virt_name)]
                        set wafpol_out ,\n[string map $l  $::WAF_pol]
                     }
                }
            }
        }
        lappend list_of_changes $string $profil_name

    }

    #puts $list_of_changes



    set new_declaration [string trimright [string map $list_of_changes $::declaration] \}\}\}\}]
    #puts $new_declaration,$pool_JSON\}\}\}\}
    set logpol_out  [tmsh::get_field_value $virt security-log-profiles]
    if { $logpol_out ne "" } {
        set logpol_out /Common/[string map {\" ""} $logpol_out]
        set l [list "LOG_POLICY_HERE" $logpol_out]
        set logpol_out [string map $l $::log_pol]
        set logpol_out ,\n$logpol_out
    }
   if { [info exists keyword]} {
        set new_declaration [string map $list_of_changes $::service_class]
        append services_declar $new_declaration\n$cltTLS_JSON$srvTLS_JSON$snat_ptr$irule_ptr \}]$wafpol_out$logpol_out\n$::white_spaces\}$irule_json$snatpoolJSON$pool_JSON\n$::white_spaces\}\n\n
    } else {
       puts "--------------------------------------------------------------------------"
       puts [string trimright $new_declaration$cltTLS_JSON$srvTLS_JSON$snat_ptr$irule_ptr \}]$wafpol_out$logpol_out\n$::white_spaces\}$irule_json$snatpoolJSON$pool_JSON\n\}\n\}\n\}\n\}
       puts "--------------------------------------------------------------------------"
    }
 # \} err\] \} \{
  #    puts "Error with [tmsh::get_name $virt].\n$err"
  #\}

}

    if { [info exists keyword]} {

        #lappend $AS3_class_changes $app_class_changes
        #set ls [list $AS3_class_changes $app_class_changes]
        set ls "$AS3_class_changes $app_class_changes APPLICATION_NAME_HERE $application_name"


        set st  $::AS3_class$::application_class$::tenant_class
        set new_declar [string map $ls $st]

        puts "--------------------------------------------------------------------------"
        puts "$new_declar$services_declar\n                 \}\n             \}\n       \}\n\}"
        puts "--------------------------------------------------------------------------"
    }


tmsh::cd /Common


}



proc script::init {} {

    set ::white_spaces "                    "
    set ::AS3_class {{
    "class": "AS3",
    "action": "deploy",
    "persist": true,
    "declaration": {
        "class": "ADC",
        "schemaVersion": "3.2.0",
        "id": "Export_Date:_ID_HERE",
        "target": {
           "hostname": "MANAGEMENT_IP_HERE" },
    }}}
    set ::AS3_class [string trimright $::AS3_class \}\}]

    set ::tenant_class {
              "TENANT_NAME_HERE": {
                  "class": "Tenant",
                  "defaultRouteDomain": 0,

    }}
    set ::tenant_class [string trimright $::tenant_class \}]

    set ::application_class {
            "APPLICATION_NAME_HERE": {
                "class": "Application",
                "template": "generic",
    }}
    set ::application_class [string trimright $::application_class \}]


    set ::service_class {
                 "VIRTUAL_NAME_HERE": {
                    "class": "Service_generic",
                    "remark": "DESCRIPTION_HERE",
                    "virtualPort": PORT_HERE,
                    "virtualAddresses": ["DESTINATION_IP_HERE"],
                    "redirect80": false,
                    "pool":  "POOL_NAME_HERE",
                    "profileTCP": {
                                "egress": "SERVERSIDE_TCP_PROFILE_HERE",
                                "ingress": { "bigip": "CLIENTSIDE_TCP_PROFILE_HERE" }
                    },
                    "profileHTTP": { "bigip": "HTTP_PROFILE_HERE" },
                    "persistenceMethods": [] }}





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
                        } }

    set ::cltTLS {                     "clientTLS": {
                       "bigip": "CLIENT_SSL_PROFILE_HERE"
                    }
                    }
    set ::srvTLS {                    "serverTLS": {
                       "bigip": "SERVER_SSL_PROFILE_HERE"
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
