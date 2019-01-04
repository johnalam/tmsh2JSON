# tmsh2JSON
Export F5 Big-IP config into a JSON blob suitable for declarative submission to F5 AS3 interface

tmsh is more than just a CLI.  It is a programmable shell with transaction capabilities.  Great for automation.


tmsh scripting specializes in Big-IP configuration handling and manipulation.  It is based on TCL but with F5 pre-loaded libraries.  These libraries give you tools to access and modify configuration objects such as virtuals, pools and profiles.

This tmsh script produces a JSON blob from an existing virtual server configuration.  The JSON blob can then be fed to AS3 to deploy application services and take advantage of analytics.
 

At the moment, it converts the Virtual Server configuration and pool only.  This means that the newly created application will have a new Virtual server and new Pool but will use pre-existing profiles.  For this reason, it is best to repost the JSON to the same Big-IP to ensure that the referenced objects exist.


This can be posted to AS3 on BigIQ or to AS3 on the BigIP itself.  It can also be loaded into Ansible Tower playbook or Jinja2 file.  You can also use it with Postman to create collections and workflows.


If you post the exported declaration to the same bigip, you will need to change the Virtual destination IP to avoid a conflict.

Currently, the script expects a WAF policy


It takes something like this:


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

 

 

And produces something like this:

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

 

 

script is attached.

 

Upload file to the /config directory on the Big-IP.

Install it with these commands:

 

          tmsh load config file <file_name> merge

          tmsh save sys config

 

run the script with this command:

 

         tmsh run cli script tmpl_export                                   # this exports all the virtuals in the config

         tmsh run cli script tmpl_export <virtual_name>       # this exports only the virtual specified.

