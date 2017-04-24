[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0)
# zbxmodHP

This directory contains a [Zabbix Loadable module](https://www.zabbix.com/documentation/3.2/manual/config/items/loadablemodules), which extends functionality of Zabbix Server

This module add the ability to monitor HP switch redundant protocols inside Zabbix Server address space.

This module has been developed to easily monitor an IRF stack status, LACP links and RRPP rings on HP switches. It only need  configuration of some macros and templates. After set on a host, it will automatically provide IRF, LACP and RRPP ring monitoring without any further configuration and it will dynamically adapt to any change in the switch configuration.

It can easily be adapt to other brands like Cisco or Juniper by modifying the SNMP requests.

# Prerequisite : 

To build the module download the **Zabbix source tree** corresponding to the version of your server (version 2.2 or higher) at [Zabbix download page](http://www.zabbix.com/download). 

Run the following command in the root of Zabbix source tree :  
```
# ./configure 
```


Then install the **net-snmp** lib (command for Debian or Ubuntu):
```
# sudo apt-get install libsnmp-dev
```

# Building the module

Copy the zbxmodHP folder in the root of Zabbix source tree and run (depending on your zabbix version): 
```
# make zbxmodHP-3.2
or
# make zbxmodHP-3.0
or 
# make zbx modHP-2.2
```
It will create a file **zbxmodHP.so** which is a shared library containing the loadable module. 

# Installing zbxmodHP

Zabbix server support two parameters to deal with modules:

- **LoadModulePath** – full path to the location of loadable modules, where to copy **zbxmodHP.so**
- **LoadModule** – module(s) to load at startup. The modules must be located in a directory specified by **LoadModulePath**. It is allowed to include multiple **LoadModule** parameters.

For example, to extend Zabbix server you could add the following parameters:

```
	LoadModulePath=/path/to/zabbix/install/modules/
	LoadModule=zbxmodHP.so
```

When it is done, restart the zabbix server and checked the log (/var/log/zabbix/zabbix_server.log) to make sure the module have been loaded.

```
 19689:20170424:154505.459 loaded modules: zbxmodHP.so
```

# Usage

The module provide 3 functions which are the following:
- monitor.irf 
- monitor.lacp 
- monitor.rrpp 

To use it, create a **Simple check item** (for zabbix server and proxy) or a **Zabbix agent item** (for zabbix agent).
 
Then use the function in the key field.

In case of error, the items will become unsupported therefore it is advised to check regularly the items' state.


## monitor.irf
This function return the state of the IRF stack.
Its parameters are : 
  - IP address of the snmp agent                              
  - SNMP read community of the snmp agent
  - The number of switch of the IRF stack monitored
  - The timeout request (in second) - 2s by default
  - The number of retries - 0 by defaul
The two last parameters are optional.

In case of success it returns an integer:
- 0 - Everything is OK 
- 1 - The ring is open 
- 2 - The topology has changed : more switches
- 3 - The topology has changed : switches missing
- 4 - Request Timeout	

In case of error (bad parameters or error during the execution) the module will become unsuported and an error message will be displayed on the web interface when hovering the item.

## monitor.lacp
This function return the state of the LACP links of a switch.
Its parameters are : 
  - IP address of the snmp agent                              
  - SNMP read community of the snmp agent
  - The timeout request (in second) - 2s by default
  - The number of retries - 0 by defaul
The two last parameters are optional.

In case of success it returns an string:
- Empty (no data) if everything is OK
- **Request timeout** in case of a timeout
- The name of the aggregations that are partially or totaly down	

In case of error (bad parameters or error during the execution) the module will become unsuported and an error message will be displayed on the web interface when hovering the item.

The formats of the string return are :
- *Bridge-aggregation-name* has one or more links down
- *Bridge-aggregation-name* is down

Keep it in mind in case you want to use regex to create differents trigger

## monitor.rrpp
This function return the state of the RRPP rings of a switch.
Its parameters are : 
  - IP address of the snmp agent                              
  - SNMP read community of the snmp agent
  - The timeout request (in second) - 2s by default
  - The number of retries - 0 by defaul
The two last parameters are optional.

In case of success it returns an string:
- Empty (no data) if everything is OK
- **Request timeout** in case of a timeout
- The name of the rings that have failure 

In case of error (bad parameters or error during the execution) the module will become unsuported and an error message will be displayed on the web interface when hovering the item.

The format of the string return is :
- Ring  *ring-number*  in domain *domain-number*  is failed

Keep it in mind in case you want to use regex to create differents trigger

# Examples
Macro are used as parameters in this example for a more generic usage especially to retrieve the SNMP agent IP address with the macro **{HOST.CONN}**. The others macro are either defined globaly, per template or per host. See the [Zabbix documentation](https://www.zabbix.com/documentation/3.0/manual/config/macros) for more information.


## Items configuration
The following function are put in the key field of an item.

For the IRF function the return type should be **Numeric (unsigned)** with **Decimal** format.
```
monitor.irf[{HOST.CONN},{$SNMP_COMMUNITY},{$NUMBER_SWITCHES},{$TIMEOUT},{$RETRIES}]
```

For the LACP and RRPP functions the return type should be **Text.**
```
monitor.lacp[{HOST.CONN},{$SNMP_COMMUNITY},{$TIMEOUT},{$RETRIES}]
```

```
monitor.rrpp[{HOST.CONN},{$SNMP_COMMUNITY},{$TIMEOUT},{$RETRIES}]
```

## Triggers configuration
Triggers should have a dependancy with a ping item because the function should not be executed when an host is unreachable. However, as zabbix refresh asynchronously, one item can return a timeout before being disabled by its dependency.


Triggers for IRF have the following format.

```
{monitor.irf[{HOST.CONN},{$SNMP_COMMUNITY},{$NUMBER_SWITCHES},{$TIMEOUT},{$RETRIES}].last()}=1
```
It is advised to create 4 triggers, one for each return value. 

For the LACP and the RRPP the items will return a string value which as a purpose of being display. Therefore the name of the trigger should be the following macro **{ITEM.VALUE}** in order to display the value returned.

```
{monitor.lacp[{HOST.CONN},{$SNMP_COMMUNITY},{$TIMEOUT},{$RETRIES}].nodata(60)}=0 
and {monitor.lacp[{HOST.CONN},{$SNMP_COMMUNITY},{$TIMEOUT},{$RETRIES}].regexp(timeout)}=1

{monitor.lacp[{HOST.CONN},{$SNMP_COMMUNITY},{$TIMEOUT},{$RETRIES}].nodata(60)}=0 
and {monitor.lacp[{HOST.CONN},{$SNMP_COMMUNITY},{$TIMEOUT},{$RETRIES}].regexp(is down)}=1

{monitor.lacp[{HOST.CONN},{$SNMP_COMMUNITY},{$TIMEOUT},{$RETRIES}].nodata(60)}=0 
and {monitor.lacp[{HOST.CONN},{$SNMP_COMMUNITY},{$TIMEOUT},{$RETRIES}].regexp(has one or more)}=1
```
The time set in nodata() should be defined according to the refresh time of the item and be the double. In this case, it is checked if data have been received for the last 60 seconds and the refresh time of the item is 30 seconds.

Regexp is used to distinguish the return valued.

For the RRPP the idea is the same as for the LACP. Here it is just checked if the string **timeout** is found in the string returned, if not a ring is open.

```
{monitor.rrpp[{HOST.CONN},{$SNMP_COMMUNITY},{$TIMEOUT},{$RETRIES}].nodata(60)}=0 
and {rrpp[{HOST.CONN},{$SNMP_COMMUNITY},{$TIMEOUT},{$RETRIES}].regexp(timeout)}=0

{monitor.rrpp[{HOST.CONN},{$SNMP_COMMUNITY},{$TIMEOUT},{$RETRIES}].nodata(60)}=0 
and {rrpp[{HOST.CONN},{$SNMP_COMMUNITY},{$TIMEOUT},{$RETRIES}].regexp(timeout)}=1
```

# Templates

For more detailed example you can look at the templates.

**Warning, macros should be correctly defined before using the templates**
