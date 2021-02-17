# tmsh2JSON
Export F5 Big-IP config into a JSON blob suitable for declarative submission to F5 AS3 interface

tmsh is more than just a CLI.  It is a programmable shell with transaction capabilities.  Great for automation.

tmsh scripting specializes in Big-IP configuration handling and manipulation.  It is based on TCL but with F5 pre-loaded libraries.  These libraries give you tools to access and modify configuration objects such as virtuals, pools and profiles.

This tmsh script produces a JSON blob from an existing virtual server configuration.  The JSON blob can then be fed to AS3 to decalaratively deploy application services and/or add to CI/CD pipeline.
 

At the moment, it converts the Virtual Server configuration, pool and memners, certificates and iRules.  This means that the newly created application will have a new Virtual server, Pool and iRules but will use pre-existing profiles and WAF policy if one is attached.  For this reason, the referenced profiles and WAF policy need to exist on the Big-IP you target with resulting AS3 decalartion.


The resulting declaration can be posted to AS3 on BigIQ or to AS3 on the BigIP itself.  It can also be loaded into Ansible Tower playbook or Jinja2 file or used with Postman to create collections and workflows.


If you post the exported declaration to the same bigip, you will need to first change the Virtual destination IP to avoid a conflict.

The script will include a reference to the WAF policy if one is attached to the virtual server properties.

 

USAGE:

The script needs the tmsh shell as well as access to the bigip live configuration and should be installed on the BigIP.  

There are multiple ways to install the script on the Big-IP.

Method 1:
    Copy the "AS3_tmpl_export.tcl" file to the /config directory on the Big-IP.

    Once copied, you can add the script to the running Big-IP configuration from the bash sehll prompt like this:

            tmsh load config file <file_name> merge

    Save it to permanent configuration like this:

            tmsh save sys config


Method 2:
    Use curl tool as well as the file "AS3_tmpl_export_JSON_for_API_post" as follows:
    curl -sk -u admin:password http://<BigIP hostname>/mgmt/tm/cli/script -H "Content-Type: application/json" -X POST -d "@AS3_export_script_JSON_for_API_post"


Method 3:
    logon to BigIP CLI and use tmsh to create the script.
    ssh admin@hostname
    tmsh #if not already in tmsh shell
    cli script
    create tmpl_export

    a vi screen will start, paste the content of AS3_tmpl_export.tcl and save and exit vi.

    then do:  save sys config



 
run the script from the BigIP bash shell prompt or from an ansible playbook with one of these commands:

         tmsh run cli script tmpl_export -k keyword                    # this exports all the virtuals in the config
         tmsh run cli script tmpl_export -k keyword -p partition       # this exports only the virtual who's name or description contain the keyword.
         tmsh run cli script tmpl_export -k <IP address>               # this exports only the virtual who's IP address match the one specified.

If you login diretly into the tmah shell (not bash), you run run the above commands like this:

          load config file <file_name> merge
          save sys config
          run cli script tmpl_export -k <keyword or IP address> -p partition


You can also run the script using REST API:
    curl -sk -u admin:password http://<BigIP hostname>/mgmt/tm/util/bash -H "Content-Type: application/json" -X POST -d '{"command": "run", "utilCmdArgs": "-c \'tmsh run cli script tmpl_export -k keyword -p partition\'"}'


In examples above, Keyword can be anything found in the virtual name or virtual description, or pool name.  It can also be an IP address.  Partition is any partition name.  If partition is specified the script will look for the keyword in that partition only.  If partition is not specified, the script will search all the partition for a match to the keyword.

You must specify a keyword with the -k switch.




The script converts a virtual server configuration such as the following into a decalaration shown below:


ltm virtual export_me {
    description "This is for export.  Export this description."
    destination 10.1.30.30:https
    ip-protocol tcp
    mask 255.255.255.255
    policies {
        linux-high { }
    }
    pool test-pool
    profiles {
	ASM_asm-policy-linux-high-security_policy { }
        clientssl {
		context clientside
        }
        http { }
        serverssl {
		context serverside
        }

        tcp-lan-optimized {
		context serverside
        }

        tcp-wan-optimized {
		context clientside
        }

        websecurity { }
    }
    source 0.0.0.0/0
    source-address-translation {
        type automap
    }

    translate-address enabled
    translate-port enabled
    vs-index 2
}


Below is the exported AS3 declaration from virtual configuration above:

{
  "class": "AS3",
  "action": "deploy",
  "persist": true,
  "declaration": {
  "class": "ADC",
  "schemaVersion": "3.2.0",
  "id": "test",
  "target": {
  "hostname": "10.1.1.10" },

  "AS3_Exports": {
  "class": "Tenant",
  "defaultRouteDomain": 0,

  "export_me": {
  "class": "Application",
  "template": "https",
  "serviceMain": {
  "class": "Service_HTTPS",
  "remark": "export_me - This is for export. Export this description. ",
  "virtualPort": 443,
  "clientTLS": {
  "bigip": "/Common/serverssl"
  },

  "virtualAddresses": ["10.1.20.110"],
  "redirect80": false,
  "pool": "testpool",
  "profileTCP": {
  "egress": "wan",
  "ingress": { "bigip": "/Common/tcp" } },
  "profileHTTP": { "bigip": "/Common/custom_http" },
  "serverTLS": { "bigip": "/Common/clientssl" },
  "persistenceMethods": [],
  "policyWAF": {
  "bigip": "/Common/asm-policy-linux-high-security_policy"
  },

  "securityLogProfiles": [{ "bigip":"/Common/Log all requests"}]
  }

  , "testpool": { "class": "Pool", "monitors": [ "http" ],
  "reselectTries": 2, "loadBalancingMode": "least-connections-member",
  "serviceDownAction": "reset",
  "members": [{
  "servicePort": 80,
  "serverAddresses": [ "10.1.10.113","10.1.10.112" ] } ]

  }

  }}}}