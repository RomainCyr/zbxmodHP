/*
 ** Copyright (C) 2017 Romain CYRILLE
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation; either version 2 of the License, or
 ** (at your option) any later version.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software
 ** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 **/

#include "sysinc.h"
#include "module.h"
#include "zbxtypes.h"
#include "common.h"
#include "log.h"
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>

#define MAX_IRF_SWITCHES 10
#define MAX_PORT_AGG 16
#define MAX_BULK_REPETITION 128
#define MAX_CHAR_RESULT 500
#define INADDRS 4
#define STAT_ERR_INIT 5
#define AGG_STATUS_OK 0
#define AGG_STATUS_LINK_DOWN 1
#define AGG_STATUS_DOWN 2
#define AGG_STATUS_UNKNOWN 3
#define RRPP_PRIMARY_PORT 1
#define RRPP_SECONDARY_PORT 2
#define RRPP_UNKNOWN 0
#define RRPP_ENABLE  1
#define RRPP_DISABLE 2
#define PORT_UP 1
#define PORT_DOWN 2

/* the variable keeps timeout setting for item processing */
static int	item_timeout = 30;

/* module SHOULD define internal functions as static and use a naming pattern different from Zabbix internal */
/* symbols (zbx_*) and loadable module API functions (zbx_module_*) to avoid conflicts                       */
static int	irf_monitoring(AGENT_REQUEST *request, AGENT_RESULT *result);
static int	lacp_monitoring(AGENT_REQUEST *request, AGENT_RESULT *result);
static int	rrpp_monitoring(AGENT_REQUEST *request, AGENT_RESULT *result);
static int is_valid_ip(const char *src);
char* itoa(int i, char b[]);
static int snmpbulkget(struct snmp_session session, struct snmp_pdu ** response, oid id_oid[MAX_OID_LEN], size_t id_len,int max_repetition);
static int snmpget(struct snmp_session session, struct snmp_pdu ** response,oid id_oid[MAX_OID_LEN], size_t id_len);

/*  This structure, that is a list, is used by the lacp_monitoring function to represent a list of Aggregation*/
struct agg_struct{
    struct agg_struct * next;
    long index;
    long ports[MAX_PORT_AGG];
    int nb_ports;
    short status;
};
typedef struct agg_struct agg_struct_t;
static void agg_struct_new(agg_struct_t ** agg);
static void agg_struct_free(agg_struct_t *agg);
static void agg_struct_init(long index, agg_struct_t *agg);
static agg_struct_t * agg_struct_exist(long index,agg_struct_t * agg);
static agg_struct_t * agg_struct_add(long index, agg_struct_t ** agg);
static void agg_struct_add_port(long port_index,agg_struct_t *agg);


/*  This structure, that is a list, is used by the rrpp_monitoring function to represent a ring*/
struct rrpp_struct{
    struct rrpp_struct * next;
    int domain;
    int ring;
    long primary_port;
    short primary_port_status;
    long secondary_port;
    short secondary_port_status;
};

typedef struct rrpp_struct rrpp_struct_t;
static void rrpp_struct_new(rrpp_struct_t ** rrpp);
static void rrpp_struct_free(rrpp_struct_t *rrpp);
static void rrpp_struct_init(short domain, short ring,rrpp_struct_t *rrpp);
static rrpp_struct_t * rrpp_struct_exist(short domain,short ring,rrpp_struct_t * rrpp);
static rrpp_struct_t * rrpp_struct_add(short domain, short ring, rrpp_struct_t ** rrpp);
static void rrpp_struct_set_port(long port_index, short selected_port, rrpp_struct_t *rrpp);
static void rrpp_struct_set_port_status(short port_status, short selected_port, rrpp_struct_t *rrpp);
static long rrpp_struct_get_port(short selected_port, rrpp_struct_t *rrpp);
static short rrpp_struct_get_port_status(short selected_port, rrpp_struct_t *rrpp);


static ZBX_METRIC keys[] =
/*      KEY             FLAG            FUNCTION                    TEST PARAMETERS */
{
    {"monitor.irf",     CF_HAVEPARAMS,  irf_monitoring,  "0,0"},
    {"monitor.lacp",    CF_HAVEPARAMS,	lacp_monitoring, "0,0"},
    {"monitor.rrpp",    CF_HAVEPARAMS,	rrpp_monitoring, "0,0"},
    {NULL}
};

/******************************************************************************
 *                                                                            *
 * Function: zbx_module_api_version                                           *
 *                                                                            *
 * Purpose: returns version number of the module interface                    *
 *                                                                            *
 * Return value: ZBX_MODULE_API_VERSION_ONE - the only version supported by   *
 *               Zabbix currently                                             *
 *                                                                            *
 ******************************************************************************/
int	zbx_module_api_version()
{
    return ZBX_MODULE_API_VERSION_ONE;
}

/******************************************************************************
 *                                                                            *
 * Function: zbx_module_item_timeout                                          *
 *                                                                            *
 * Purpose: set timeout value for processing of items                         *
 *                                                                            *
 * Parameters: timeout - timeout in seconds, 0 - no timeout set               *
 *                                                                            *
 ******************************************************************************/
void	zbx_module_item_timeout(int timeout)
{
    item_timeout = timeout;
}


/******************************************************************************
 *                                                                            *
 * Function: zbx_module_item_list                                             *
 *                                                                            *
 * Purpose: returns list of item keys supported by the module                 *
 *                                                                            *
 * Return value: list of item keys                                            *
 *                                                                            *
 ******************************************************************************/
ZBX_METRIC	*zbx_module_item_list()
{
    return keys;
}


/******************************************************************************
 *                                                                            *
 * Function: irf_monitoring                                                   *
 *                                                                            *
 * Purpose: Item to monitor irf protocol                                      *
 *                                                                            *
 * Parameters: request - structure that contains item key and parameters      *
 *              request->key - item key without parameters                    *
 *              request->nparam - number of parameters                        *
 *              request->timeout - processing should not take longer than     *
 *                                 this number of seconds                     *
 *              request->params[N-1] - pointers to item key parameters        *
 *                                                                            *
 *             result - structure that will contain result                    *
 *                                                                            *
 * Return value: SYSINFO_RET_FAIL - function failed, item will be marked      *
 *                                 as not supported by zabbix                 *
 *               SYSINFO_RET_OK - success                                     *
 *                                                                            *
 * Comment: The parameters of the request are (in order):                     *
 *              - IP address of the snmp agent                                *
 *              - SNMP read community of the snmp agent                       *
 *              - The number of switch of the IRF stack monitored             *
 *              - The timeout request (in second) - 2s by default             *
 *              - The number of retries - 0 by default                        *
 *          The two last parameters are optional                              *
 *                                                                            *
 *          In case of success the result structure will contain              *
 *          the following:                                                    *
 *               - 0 - Everything is OK                                       *
 *               - 1 - The ring is open                                       *
 *               - 2 - The topology has changed : more switches               *
 *               - 3 - The topology has changed : switches missing
 *  			 - 4 - Request Timeout		
 *
 *                                                                            *
 *          In case of failure, the result structure will contain an          *
 *          error message                                                     *
 ******************************************************************************/
static int	irf_monitoring(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    /****************** Variables ******************/
    //Structs needed for snmp request
    struct snmp_session session;
    struct snmp_pdu *response;
    struct variable_list *vars;
    
    
    //Variables holding oid to check
    oid oid_table_irf[] = {1,3,6,1,4,1,25506,2,91,4,1,3};
    int oid_len_irf = 12 ;
    
    
    //Parameters (Not mandatory parameters are initialised)
    long version = SNMP_VERSION_2c;
    long timeout = 2000000;
    int retries = 0;
    char *community;
    size_t community_len;
    char *ip_address;
    int nb_switches_monitored;
    int max_switches;
    
    
    //Others Variables
    short status;
    short nb_switches = 0;
    short ring_open = 0;
    int ret = SYSINFO_RET_OK;
    int i,flag;
    
    /****************** Get parameters ******************/
    //Check if mandatory parameters are provided
    if(request->nparam <3){
        SET_MSG_RESULT(result, strdup("Parameters Missing"));
        ret =  SYSINFO_RET_FAIL;
    }
    //Check IP address is valid
    ip_address = get_rparam(request, 0);
    if(is_valid_ip(ip_address)){
        SET_MSG_RESULT(result, strdup("Invalid IP Address"));
        ret = SYSINFO_RET_FAIL;
    }
    //Get Community
    community = get_rparam(request, 1);
    community_len = strlen(community);
    //Get the number of switches monitored
    nb_switches_monitored = atoi(get_rparam(request, 2));
    if(nb_switches_monitored>MAX_IRF_SWITCHES || nb_switches_monitored<1){
        SET_MSG_RESULT(result, strdup("Number of monitored switches invalid"));
        ret = SYSINFO_RET_FAIL;
    }
    max_switches = (nb_switches_monitored + 1)*2;
    //Get Timeout if provided
    if(request->nparam >3){
        timeout = atoi(get_rparam(request, 3))*1000000;
    }
    //Get Retries if provided
    if(request->nparam >4){
        retries = atoi(get_rparam(request, 4));
    }
    
    /****************** Main code ******************/
    //Init SNMP Session
    snmp_sess_init( &session );
    session.version = version;
    session.timeout = timeout;
    session.retries = retries;
    session.community = community;
    session.community_len = community_len;
    session.peername = ip_address;
    
    //Send the request
    status = snmpbulkget(session, &response, oid_table_irf, oid_len_irf, max_switches);
    
    //If success, analyse the data received
    if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
        for(vars = response->variables; vars; vars = vars->next_variable) {
            i = 0;
            flag = 1;
            while(i<oid_len_irf && flag){
                //Compare the oid of the response with the oid to check
                if(oid_table_irf[i]!=vars->name[i]){
                    flag =  0;
                }
                i++;
            }
            //If it is the same oid, check the value
            if(flag && vars->type == ASN_INTEGER){
                nb_switches ++;
                //If one of the value is not 1 (port status is UP) then the ring is open
                if(*(vars->val.integer) != 1) ring_open = 1;
            }
        }
        
        //Set the return depending on the result
        if(nb_switches%2 !=0){
            SET_MSG_RESULT(result, strdup("Unknown error in SNMP session"));
            ret = SYSINFO_RET_FAIL;
        }
        nb_switches=nb_switches/2;
        
        if(nb_switches == nb_switches_monitored && !ring_open){
            SET_UI64_RESULT(result, 0);
            ret = SYSINFO_RET_OK;
        }
        if(nb_switches == nb_switches_monitored && ring_open){
            SET_UI64_RESULT(result, 1);
            ret = SYSINFO_RET_OK;
        }
        if(nb_switches>nb_switches_monitored){
            SET_UI64_RESULT(result, 2);
            ret = SYSINFO_RET_OK;
        }
        if (nb_switches<nb_switches_monitored){
            SET_UI64_RESULT(result, 3);
            ret = SYSINFO_RET_OK;
        }
    } else {
        //If failure, return the error message
        if (status == STAT_SUCCESS){
            SET_MSG_RESULT(result, strdup(snmp_errstring(response->errstat)));
            ret = SYSINFO_RET_FAIL;
        }else if (status == STAT_TIMEOUT){
            SET_UI64_RESULT(result, 4);
            ret = SYSINFO_RET_OK;
        }
        else{
            SET_MSG_RESULT(result, strdup("Unknown error in SNMP session"));
            ret = SYSINFO_RET_FAIL;
        }
    }
    //Free the used pdu structure
    snmp_free_pdu(response);
    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: lacp_monitoring                                                  *
 *                                                                            *
 * Purpose: Item to monitor lacp protocol                                     *
 *                                                                            *
 * Parameters: request - structure that contains item key and parameters      *
 *              request->key - item key without parameters                    *
 *              request->nparam - number of parameters                        *
 *              request->timeout - processing should not take longer than     *
 *                                 this number of seconds                     *
 *              request->params[N-1] - pointers to item key parameters        *
 *                                                                            *
 *             result - structure that will contain result                    *
 *                                                                            *
 * Return value: SYSINFO_RET_FAIL - function failed, item will be marked      *
 *                                 as not supported by zabbix                 *
 *               SYSINFO_RET_OK - success                                     *
 *                                                                            *
 * Comment: The parameters of the request are (in order):                     *
 *              - IP address of the snmp agent                                *
 *              - SNMP read community of the snmp agent                       *
 *              - The timeout request (in second) - 2s by default             *
 *              - The number of retries - 0 by default                        *
 *          The two last parameters are optional                              *
 *                                                                            *
 *          In case of success the result structure will contain              *
 *          the following:                                                    *
 *               - No data if everything is OK  							  *
 *				 - "Request timeout" in case of a timeout                     *
 *               - The name of the aggregation that are partially or          *
 *                 totaly down												  *
 *                                                                            *
 *          In case of failure, the result structure will contain an          *
 *          error message                                                     *
 ******************************************************************************/
static int	lacp_monitoring(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    
    
    /****************** Variables ******************/
    //Structs needed for snmp request
    struct snmp_session session;
    struct snmp_pdu *response;
    struct variable_list *vars;
    oid oid_table_tmp[MAX_OID_LEN];
    size_t oid_len_tmp = MAX_OID_LEN;
    
    
    //Variables holding oid to check
    oid oid_table_agg_port_list[] = {1,2,840,10006,300,43,1,1,2,1,1};
    int oid_len_agg_port_list = 11 ;
    
    oid oid_table_agg_port_attached_id[] = {1,2,840,10006,300,43,1,2,1,1,13};
    int oid_len_agg_port_attached_id = 11 ;
    
    
    oid oid_table_if_oper_status[] = {1,3,6,1,2,1,2,2,1,8};
    int oid_len_if_oper_status = 10 ;
    
    
    oid oid_table_if_desc[] = {1,3,6,1,2,1,2,2,1,2};
    int oid_len_if_desc = 10 ;
    
    
    //Parameters (Not mandatory parameters are initialised)
    long version = SNMP_VERSION_2c;
    long timeout = 2000000;
    int retries = 0;
    char *community;
    size_t community_len;
    char *ip_address;
    
    //Aggregation structure variable
    agg_struct_t *agg = NULL;
    agg_struct_t * agg_tmp = NULL;
    long last_index;
    int link_down;
    
    
    //Other Variables
    short status;
    short finish;
    int ret = SYSINFO_RET_OK;
    int i;
    char tmp_res[MAX_CHAR_RESULT];
    char msg_is_down[]="is down\n";
    short len_is_down = 9;
    char msg_has_link_down[28]="has one or more links down\n";
    short len_has_link_down = 28;
    char msg_too_many[18]="Too many results\n";
    short len_too_many = 18;
    short already_written;
    
    
    /****************** Get parameters ******************/
    //Get parameters
    if(request->nparam <2){     //Check if mandatory parameters are provided
        SET_MSG_RESULT(result, strdup("Parameters Missing"));
        ret =  SYSINFO_RET_FAIL;
    }
    ip_address = get_rparam(request, 0);
    
    if(is_valid_ip(ip_address)){
        SET_MSG_RESULT(result, strdup("Invalid IP Address"));
        ret = SYSINFO_RET_FAIL;
    }
    
    community = get_rparam(request, 1);
    community_len = strlen(community);
    
    if(request->nparam >2){
        timeout = atoi(get_rparam(request, 2))*1000000;
    }
    if(request->nparam >3){
        retries = atoi(get_rparam(request, 3));
    }
    //zabbix_log(LOG_LEVEL_INFORMATION, "IP:%s Com:%s",ip_address,community);
    /****************** Main code ******************/
    //Init SNMP Session
    snmp_sess_init(&session);
    session.version = version;
    session.timeout = timeout;
    session.retries = retries;
    session.community = community;
    session.community_len = community_len;
    session.peername = ip_address;
    
    /********************************************************************
     * The first step is to check if the switch has any aggregation.    *
     * As the bulkrequest may not get all the subtree in one request,   *
     * a loop is made until all the nodes have been retrieved           *
     * If there is any aggregation then it is save in an aggregation    *
     * structure.                                                       *
     *******************************************************************/
    
    //Init the differents variables used for this step
    for(i=0;i<oid_len_agg_port_list;i++)oid_table_tmp[i] = oid_table_agg_port_list[i];
    oid_len_tmp = oid_len_agg_port_list;
    finish = 1;
    last_index = 0;
    status = STAT_SUCCESS;
    while(finish && !status){
        //If more than one bulkrequest is necessery to get the all subtree
        //then the next node to start the second request is the last index retrieve
        oid_len_tmp = oid_len_agg_port_list;
        if(last_index !=0){
            oid_table_tmp[oid_len_tmp]=last_index;
            oid_len_tmp++;
        }
        
        //Send the request
        status = snmpbulkget(session, &response, oid_table_tmp, oid_len_tmp, MAX_BULK_REPETITION);
        
        //If success, analyse the data received
        if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
            vars = response->variables;
            while(vars !=NULL && finish) {
                i = 0;
                while(i<oid_len_agg_port_list && finish){
                    //Compare the oid of the response with the oid to check
                    //If the subtstree is different then the loop stop
                    if(oid_table_agg_port_list[i]!=vars->name[i]){
                        finish=0;
                    }
                    i++;
                }
                //If it is the same oid then save the aggregation index in an aggregation structure
                if(finish){
                    agg_struct_add(vars->name[i], &agg);
                    last_index = vars->name[i];
                }
                vars = vars->next_variable;
            }
            
        } else {
            //If failure, return the error message
            if (status == STAT_SUCCESS){
                SET_MSG_RESULT(result, strdup(snmp_errstring(response->errstat)));
                ret = SYSINFO_RET_FAIL;
            }
        }
        //Free the used structure
        snmp_free_pdu(response);
    }
    
    /********************************************************************
     * If the switch has no aggregation configured then it is not       *
     * needed to continue.                                              *
     * If it has aggregation then man need to get all the port attached *
     * to this aggregation. Once again, as the bulkrequest may not get  *
     * all the subtree in one request, a loop is made until all the     *
     * nodes have been retrieved                                        *
     *******************************************************************/
    finish = 1;
    if(agg != NULL && finish){
        
        //Init the differents variables used for this step
        for(i=0;i<oid_len_agg_port_attached_id;i++)oid_table_tmp[i] = oid_table_agg_port_attached_id[i];
        oid_len_tmp = oid_len_agg_port_attached_id;
        finish = 1;
        last_index = 0;
        while(finish & !status){
            //If more than one bulkrequest is necessery to get the all subtree
            //then the next node to start the second request is the last index retrieve
            oid_len_tmp = oid_len_agg_port_attached_id;
            if(last_index !=0){
                oid_table_tmp[oid_len_tmp]=last_index;
                oid_len_tmp++;
            }
            //Send the request
            status = snmpbulkget(session, &response, oid_table_tmp, oid_len_tmp, MAX_BULK_REPETITION);
            //If success, analyse the data received
            if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
                vars = response->variables;
                while(vars !=NULL && finish){
                    i = 0;
                    while(i<oid_len_agg_port_attached_id && finish){
                        //Compare the oid of the response with the oid to check
                        //If the subtstree is different then the loop stop
                        if(oid_table_agg_port_attached_id[i]!=vars->name[i]){
                            finish=0;
                        }
                        i++;
                    }
                    //If it the same oid, check the value
                    if(finish){
                        last_index = vars->name[i];
                        //If the value is different from zero then the port is attached to an aggregation
                        if(vars->type == ASN_INTEGER && *vars->val.integer !=0){
                            //If the aggregation has been retrieved at the previous step
                            //then we had this port to the aggregation
                            agg_tmp = agg_struct_exist(*vars->val.integer, agg);
                            if(agg_tmp != NULL)agg_struct_add_port(vars->name[i], agg_tmp);
                        }
                    }
                    vars = vars->next_variable;
                }
            } else {
                //If failure, return the error message
                if (status == STAT_SUCCESS){
                    SET_MSG_RESULT(result, strdup(snmp_errstring(response->errstat)));
                    ret = SYSINFO_RET_FAIL;
                }
                
            }
            //Free the used structure
            snmp_free_pdu(response);
        }
        
        /********************************************************************
         * The next step is to get the status of every port attached        *
         * to an aggregation and deduce the state of the aggregations       *
         *******************************************************************/
        agg_tmp = agg;
        agg_tmp->status = AGG_STATUS_OK; //By default the status of an aggregation is OK
        link_down = 0;
        last_index = 0;
        finish = 1;
        while(agg_tmp !=NULL && finish && !status){
            //If the aggregation has no port it is skipped
            if(agg_tmp->nb_ports!=0){
                //Set the oid of status of the port to retrieve
                for(i=0;i<oid_len_if_oper_status;i++)oid_table_tmp[i] = oid_table_if_oper_status[i];
                oid_len_tmp = oid_len_if_oper_status;
                if(last_index<MAX_PORT_AGG)oid_table_tmp[oid_len_tmp++] = agg_tmp->ports[last_index++];
                
                //Send the request
                status = snmpget(session, &response, oid_table_tmp, oid_len_tmp);
                //If success, analyse the data received
                if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
                    vars = response->variables;
                    while(vars !=NULL && finish) {
                        i = 0;
                        while(i<oid_len_if_oper_status && finish){
                            //Compare the oid of the response with the oid to check
                            //If the subtstree is different, there is an error and the loop is stopped
                            if(oid_table_tmp[i]!=vars->name[i]){
                                SET_MSG_RESULT(result, strdup("Unknown error in SNMP session"));
                                ret = SYSINFO_RET_FAIL;
                                finish = 0;
                            }
                            i++;
                        }
                        //If a link is different from UP then one link is down in the aggregation
                        if(finish && vars->type == ASN_INTEGER && *vars->val.integer!=PORT_UP){
                            agg_tmp->status = AGG_STATUS_LINK_DOWN;
                            link_down++; //Use to count the link down in the aggregation
                        }
                        vars = vars->next_variable;
                    }
                    
                } else {
                    //If failure, return the error message
                    if (status == STAT_SUCCESS){
                        SET_MSG_RESULT(result, strdup(snmp_errstring(response->errstat)));
                        ret = SYSINFO_RET_FAIL;
                    }            }
                //Free the used structure
                snmp_free_pdu(response);
            }
            //When the status of all the port of the aggregation have been retrieved
            //the result are analysed to deduce is the aggregation is completly down
            //Then the next aggregation is load
            if(finish && agg_tmp->nb_ports<=last_index){
                if(agg_tmp->nb_ports == link_down && agg_tmp->nb_ports != 0){
                    agg_tmp->status = AGG_STATUS_DOWN;
                }
                link_down = 0;
                agg_tmp = agg_tmp->next;
                if(agg_tmp!=NULL)agg_tmp->status = AGG_STATUS_OK; //By default the status of an aggregation is OK
                last_index = 0;
            }
            
        }
        
        /********************************************************************
         * The last step is to get the description of any aggregation       *
         * that doesn't have a AGG_STATUS_OK                                *
         *******************************************************************/
        agg_tmp = agg;
        already_written = 0;
        while (agg_tmp!=NULL && !status && finish) {
            //Get the description of the aggregation only if not OK
            if(agg_tmp ->status !=AGG_STATUS_OK){
                //Set the oid of the description of the interface to retrieved
                for(i=0;i<oid_len_if_desc;i++)oid_table_tmp[i] = oid_table_if_desc[i];
                oid_len_tmp = oid_len_if_desc;
                oid_table_tmp[oid_len_tmp++] = agg_tmp->index;
                
                //Send the request
                status = snmpget(session, &response, oid_table_tmp, oid_len_tmp);
                if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
                    vars = response->variables;
                    while(vars !=NULL && finish) {
                        i = 0;
                        while(i<oid_len_if_desc && finish){
                            //Compare the oid of the response with the oid to check
                            //If the subtstree is different, there is an error and the loop is stopped
                            if(oid_table_tmp[i]!=vars->name[i]){
                                SET_MSG_RESULT(result, strdup("Unknown error in SNMP session"));
                                ret = SYSINFO_RET_FAIL;
                                finish = 0;
                            }
                            i++;
                        }
                        if(vars->type == ASN_OCTET_STR & vars->val.string!=NULL && finish){
                            //Set the result depending on the aggregation status (completely down or partially)
                            if(agg_tmp->status == AGG_STATUS_DOWN){
                                if(vars->val_len + len_is_down + len_too_many < MAX_CHAR_RESULT-already_written){
                                    for(i=0;(i<vars->val_len) && (i + already_written <MAX_CHAR_RESULT);i++){
                                        tmp_res[i+already_written]=vars->val.string[i];
                                    }
                                    already_written = already_written+i;
                                    tmp_res[already_written++]=' ';
                                    for(i=0;(i<len_is_down) && (i + already_written <MAX_CHAR_RESULT);i++){
                                        tmp_res[i+already_written] = msg_is_down[i];
                                    }
                                    already_written = already_written+i-1;
                                }
                                else
                                {
                                    for(i=0;(i<len_too_many) && (i + already_written <MAX_CHAR_RESULT);i++){
                                        tmp_res[i+already_written] = msg_too_many[i];
                                    }
                                    already_written = already_written+i-1;
                                    finish = 0;
                                }
                            }
                            if(agg_tmp->status == AGG_STATUS_LINK_DOWN){
                                if(vars->val_len+len_has_link_down+len_too_many<MAX_CHAR_RESULT-already_written){
                                    if(vars->val_len + len_has_link_down + len_too_many < MAX_CHAR_RESULT-already_written){
                                        for(i=0;(i<vars->val_len) && (i + already_written <MAX_CHAR_RESULT);i++){
                                            tmp_res[i+already_written]=vars->val.string[i];
                                        }
                                        already_written = already_written+i;
                                        tmp_res[already_written++]=' ';
                                        for(i=0;(i<len_has_link_down) && (i + already_written <MAX_CHAR_RESULT);i++){
                                            tmp_res[i+already_written] = msg_has_link_down[i];
                                        }
                                        already_written = already_written+i-1;
                                    }
                                    else
                                    {
                                        for(i=0;(i<len_too_many) && (i + already_written <MAX_CHAR_RESULT);i++){
                                            tmp_res[i+already_written] = msg_too_many[i];
                                        }
                                        already_written = already_written+i-1;
                                        finish = 0;
                                    }
                                }
                            }
                            vars = vars->next_variable;
                        }
                    }
                    
                } else {
                    //If failure, return the error message
                    if (status == STAT_SUCCESS){
                        SET_MSG_RESULT(result, strdup(snmp_errstring(response->errstat)));
                        ret = SYSINFO_RET_FAIL;
                    }
                }
                //Free the used structure
                snmp_free_pdu(response);
            }
            agg_tmp = agg_tmp->next;
        }
        if(already_written !=0){
            SET_STR_RESULT(result, strdup(tmp_res));
            ret = SYSINFO_RET_OK;
        }
    }else{
        ret = SYSINFO_RET_OK;
    }
    if(status !=STAT_SUCCESS){
        
        if (status == STAT_TIMEOUT){
            SET_STR_RESULT(result, strdup("Request timeout"));
            ret = SYSINFO_RET_OK;
        }else if(status == STAT_ERR_INIT){
            SET_MSG_RESULT(result, strdup("Error when Initializing SNMP session"));
            ret = SYSINFO_RET_FAIL;
        }
        else{
            SET_MSG_RESULT(result, strdup("Unknown error in SNMP session"));
            ret = SYSINFO_RET_FAIL;
        }
    }
    //Free the aggregation structures
    agg_struct_free(agg);
    return ret;
}

/******************************************************************************
 *                                                                            *
 * Function: rrpp_monitoring                                        		  *
 *                                                                            *
 * Purpose: Item to monitor RRPP protocol                                     *
 *                                                                            *
 * Parameters: request - structure that contains item key and parameters      *
 *              request->key - item key without parameters                    *
 *              request->nparam - number of parameters                        *
 *              request->timeout - processing should not take longer than     *
 *                                 this number of seconds                     *
 *              request->params[N-1] - pointers to item key parameters        *
 *                                                                            *
 *             result - structure that will contain result                    *
 *                                                                            *
 * Return value: SYSINFO_RET_FAIL - function failed, item will be marked      *
 *                                 as not supported by zabbix                 *
 *               SYSINFO_RET_OK - success                                     *
 *                                                                            *
 * Comment: The parameters of the request are (in order):                     *
 *              - IP address of the snmp agent                                *
 *              - SNMP read community of the snmp agent                       *
 *              - The timeout request (in second) - 2s by default             *
 *              - The number of retries - 0 by default                        *
 *          The two last parameters are optional                              *
 *                                                                            *
 *          In case of success the result structure will contain              *
 *          the following:                                                    *
 *               - No data if everything is OK                                *
 *				 - "Request timeout" in case of a timeout                     *
 *               - The name of the rings that have failure                    *
 *                                                                            *
 *          In case of failure, the result structure will contain an          *
 *          error message                                                     *
 ******************************************************************************/
static int	rrpp_monitoring(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    /****************** Variables ******************/
    //Structs needed for snmp request
    struct snmp_session session;
    struct snmp_pdu *response;
    struct variable_list *vars;
    oid oid_table_tmp[MAX_OID_LEN];
    size_t oid_len_tmp = MAX_OID_LEN;
    
    
    //Variables holding oid to check
    oid oid_table_rrpp_enable[] = {1,3,6,1,4,1,25506,2,45,1,1,0};
    int oid_len_rrpp_enable = 12 ;
    
    oid oid_table_rrpp_ring_status[] = {1,3,6,1,4,1,25506,2,45,2,2,1,2};
    int oid_len_rrpp_ring_status = 13 ;
    
    oid oid_table_rrpp_ring_primary_port[] = {1,3,6,1,4,1,25506,2,45,2,2,1,6};
    int oid_len_rrpp_ring_primary_port = 13 ;
    
    oid oid_table_rrpp_ring_secondary_port[] = {1,3,6,1,4,1,25506,2,45,2,2,1,7};
    int oid_len_rrpp_ring_secondary_port = 13 ;
    
    oid oid_table_if_oper_status[] = {1,3,6,1,2,1,2,2,1,8};
    int oid_len_if_oper_status = 10 ;
    
    
    //Parameters (Not mandatory parameters are initialised)
    long version = SNMP_VERSION_2c;
    long timeout = 2000000;
    int retries = 0;
    char *community;
    size_t community_len;
    char *ip_address;
    
    //Aggregation structure variable
    rrpp_struct_t * rrpp = NULL;
    rrpp_struct_t * rrpp_tmp = NULL;
    short last_domain;
    short last_ring;
    short current_port;
    
    
    //Other Variables
    short status;
    short finish;
    short rings_enabled = 0;
    short ret = SYSINFO_RET_FAIL;
    short already_written;
    char tmp_res[MAX_CHAR_RESULT];
    char msg_ring_failed[31]="Ring    in domain    is failed\n";
    short len_ring_failed = 31;
    short pos_ring = 5;
    short pos_domain = 19;
    char msg_buf[2];
    char msg_too_many[18]="Too many results\n";
    short len_too_many = 18;
    int i;
    
    /****************** Get parameters ******************/
    //Get parameters
    if(request->nparam <2){     //Check if mandatory parameters are provided
        SET_MSG_RESULT(result, strdup("Parameters Missing"));
        ret =  SYSINFO_RET_FAIL;
    }
    ip_address = get_rparam(request, 0);
    
    if(is_valid_ip(ip_address)){
        SET_MSG_RESULT(result, strdup("Invalid IP Address"));
        ret = SYSINFO_RET_FAIL;
    }
    
    community = get_rparam(request, 1);
    community_len = strlen(community);
    
    if(request->nparam >2){
        timeout = atoi(get_rparam(request, 2))*1000000;
    }
    if(request->nparam >3){
        retries = atoi(get_rparam(request, 3));
    }
    
    /****************** Main code ******************/
    //Init SNMP Session
    snmp_sess_init(&session);
    session.version = version;
    session.timeout = timeout;
    session.retries = retries;
    session.community = community;
    session.community_len = community_len;
    session.peername = ip_address;
    
    /********************************************************************
     * The first step is to check if the switch has RRPP enable.        *
     *******************************************************************/
    finish = 1;
    status = STAT_SUCCESS;
    //Send the request
    status = snmpget(session, &response, oid_table_rrpp_enable, oid_len_rrpp_enable);
    
    //If success, analyse the data received
    if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
        vars = response->variables;
        i=0;
        while(i<oid_len_rrpp_enable && finish){
            //Compare the oid of the response with the oid to check
            //If the subtstree is different, there is an error and the loop is stopped
            if(oid_table_rrpp_enable[i]!=vars->name[i]){
                SET_MSG_RESULT(result, strdup("Unknown error in SNMP session"));
                ret = SYSINFO_RET_FAIL;
                finish = 0;
            }
            i++;
        }
        if(vars->type !=ASN_INTEGER){
            SET_MSG_RESULT(result, strdup("Unknown error in SNMP session"));
            ret = SYSINFO_RET_FAIL;
            finish = 0;
        }
        else if(*vars->val.integer==2){
            finish = 0;
            ret = SYSINFO_RET_OK;
        }
    } else {
        //If failure, return the error message
        if (status == STAT_SUCCESS){
            SET_MSG_RESULT(result, strdup(snmp_errstring(response->errstat)));
            ret = SYSINFO_RET_FAIL;
        }
    }
    //Free the used structure
    snmp_free_pdu(response);
    
    
    /********************************************************************
     * If the switch has no rrpp enable configured then it is not       *
     * needed to continue.                                              *
     * If it has rrpp enable then man need to get all the domain and    *
     * enabled rings                                                    *
     *******************************************************************/
    if(finish && !status){
        //Init the differents variables used for this step
        for(i=0;i<oid_len_rrpp_ring_status;i++)oid_table_tmp[i] = oid_table_rrpp_ring_status[i];
        oid_len_tmp = oid_len_rrpp_ring_status;
        finish = 1;
        last_domain = 0;
        last_ring = 0;
        while(finish & !status){
            //If more than one bulkrequest is necessery to get the all subtree
            //then the next node to start the second request is the last domain and ring retrieved
            oid_len_tmp = oid_len_rrpp_ring_status;
            if(last_domain !=0 && last_ring !=0){
                oid_table_tmp[oid_len_tmp++]=last_domain;
                oid_table_tmp[oid_len_tmp++]=last_ring;
            }
            //Send the request
            status = snmpbulkget(session, &response, oid_table_tmp, oid_len_tmp, MAX_BULK_REPETITION);
            //If success, analyse the data received
            if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
                vars = response->variables;
                while(vars !=NULL && finish){
                    i = 0;
                    while(i<oid_len_rrpp_ring_status && finish){
                        //Compare the oid of the response with the oid to check
                        //If the subtstree is different then the loop stop
                        if(oid_table_rrpp_ring_status[i]!=vars->name[i]){
                            finish=0;
                        }
                        i++;
                    }
                    //If it the same oid, check the value
                    if(finish){
                        last_domain = vars->name[i];
                        last_ring = vars->name[i+1];
                        //Save the ring if it is enable
                        if(vars->type == ASN_INTEGER && *vars->val.integer == 1){
                            rrpp_tmp = rrpp_struct_add(last_domain, last_ring, &rrpp);
                            rings_enabled = 1;
                        }
                    }
                    vars = vars->next_variable;
                }
            } else {
                //If failure, return the error message
                if (status == STAT_SUCCESS){
                    SET_MSG_RESULT(result, strdup(snmp_errstring(response->errstat)));
                    ret = SYSINFO_RET_FAIL;
                }
                
            }
            //Free the used structure
            snmp_free_pdu(response);
        }
        /*******************************************************************
         * The next step is to get the primary port of every enabled ring *
         *******************************************************************/
        for(i=0;i<oid_len_rrpp_ring_primary_port;i++)oid_table_tmp[i] = oid_table_rrpp_ring_primary_port[i];
        oid_len_tmp = oid_len_rrpp_ring_primary_port;
        finish = 1;
        last_domain = 0;
        last_ring = 0;
        while(finish & !status && rings_enabled){
            //If more than one bulkrequest is necessery to get the all subtree
            //then the next node to start the second request is the last domain and ring retrieved
            oid_len_tmp = oid_len_rrpp_ring_primary_port;
            if(last_domain !=0 && last_ring !=0){
                oid_table_tmp[oid_len_tmp++]=last_domain;
                oid_table_tmp[oid_len_tmp++]=last_ring;
            }
            //Send the request
            status = snmpbulkget(session, &response, oid_table_tmp, oid_len_tmp, MAX_BULK_REPETITION);
            //If success, analyse the data received
            if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
                vars = response->variables;
                while(vars !=NULL && finish){
                    i = 0;
                    while(i<oid_len_rrpp_ring_primary_port && finish){
                        //Compare the oid of the response with the oid to check
                        //If the subtstree is different then the loop stop
                        if(oid_table_rrpp_ring_primary_port[i]!=vars->name[i]){
                            finish=0;
                        }
                        i++;
                    }
                    //If it the same oid, check the value
                    if(finish){
                        last_domain = vars->name[i];
                        last_ring = vars->name[i+1];
                        //Save the primary-port index
                        if(vars->type == ASN_INTEGER ){
                            rrpp_tmp = rrpp_struct_exist(last_domain, last_ring, rrpp);
                            if(rrpp_tmp!=NULL)rrpp_struct_set_port(*vars->val.integer, RRPP_PRIMARY_PORT, rrpp_tmp);
                        }
                    }
                    vars = vars->next_variable;
                }
            } else {
                //If failure, return the error message
                if (status == STAT_SUCCESS){
                    SET_MSG_RESULT(result, strdup(snmp_errstring(response->errstat)));
                    ret = SYSINFO_RET_FAIL;
                }
                
            }
            //Free the used structure
            snmp_free_pdu(response);
            
        }
        
        /*******************************************************************
         * The next step is to get the secondary port of every enable ring *
         *******************************************************************/
        for(i=0;i<oid_len_rrpp_ring_secondary_port;i++)oid_table_tmp[i] = oid_table_rrpp_ring_secondary_port[i];
        oid_len_tmp = oid_len_rrpp_ring_secondary_port;
        finish = 1;
        last_domain = 0;
        last_ring = 0;
        while(rings_enabled && finish & !status ){
            //If more than one bulkrequest is necessery to get the all subtree
            //then the next node to start the second request is the last domain and ring retrieved
            oid_len_tmp = oid_len_rrpp_ring_secondary_port;
            if(last_domain !=0 && last_ring !=0){
                oid_table_tmp[oid_len_tmp++]=last_domain;
                oid_table_tmp[oid_len_tmp++]=last_ring;
            }
            //Send the request
            status = snmpbulkget(session, &response, oid_table_tmp, oid_len_tmp, MAX_BULK_REPETITION);
            //If success, analyse the data received
            if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
                vars = response->variables;
                while(vars !=NULL && finish){
                    i = 0;
                    while(i<oid_len_rrpp_ring_secondary_port && finish){
                        //Compare the oid of the response with the oid to check
                        //If the subtstree is different then the loop stop
                        if(oid_table_rrpp_ring_secondary_port[i]!=vars->name[i]){
                            finish=0;
                        }
                        i++;
                    }
                    //If it the same oid, check the value
                    if(finish){
                        last_domain = vars->name[i];
                        last_ring = vars->name[i+1];
                        //Save the secondary-port index
                        if(vars->type == ASN_INTEGER ){
                            rrpp_tmp = rrpp_struct_exist(last_domain, last_ring, rrpp);
                            if(rrpp_tmp!=NULL)rrpp_struct_set_port(*vars->val.integer, RRPP_SECONDARY_PORT, rrpp_tmp);
                        }
                    }
                    vars = vars->next_variable;
                }
            } else {
                //If failure, return the error message
                if (status == STAT_SUCCESS){
                    SET_MSG_RESULT(result, strdup(snmp_errstring(response->errstat)));
                    ret = SYSINFO_RET_FAIL;
                }
                
            }
            //Free the used structure
            snmp_free_pdu(response);
        }
        
        /********************************************************************
         * The next step is to get the status of every primary and          *
         * secondary port                                                   *
         *******************************************************************/
        rrpp_tmp = rrpp;
        finish = 1;
        current_port = RRPP_PRIMARY_PORT;
        while(finish && !status && rings_enabled && rrpp_tmp !=NULL){
            //If the port of the ring has 0 as index it is skipped
            if(rrpp_struct_get_port(current_port, rrpp_tmp)!=0){
                //Set the oid of status of the port to retrieve
                for(i=0;i<oid_len_if_oper_status;i++)oid_table_tmp[i] = oid_table_if_oper_status[i];
                oid_len_tmp = oid_len_if_oper_status;
                oid_table_tmp[oid_len_tmp++] = rrpp_struct_get_port(current_port, rrpp_tmp);
                
                //Send the request
                status = snmpget(session, &response, oid_table_tmp, oid_len_tmp);
                //If success, analyse the data received
                if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
                    vars = response->variables;
                    i = 0;
                    while(i<oid_len_if_oper_status && finish){
                        //Compare the oid of the response with the oid to check
                        //If the subtstree is different, there is an error and the loop is stopped
                        if(oid_table_tmp[i]!=vars->name[i]){
                            SET_MSG_RESULT(result, strdup("Unknown error in SNMP session"));
                            ret = SYSINFO_RET_FAIL;
                            finish = 0;
                        }
                        i++;
                    }
                    //Set the port status
                    if(finish && vars->type == ASN_INTEGER){
                        if(*vars->val.integer == PORT_UP){
                            rrpp_struct_set_port_status(PORT_UP, current_port, rrpp_tmp);
                        }else{
                            rrpp_struct_set_port_status(PORT_DOWN, current_port, rrpp_tmp);
                        }
                    }
                } else {
                    //If failure, return the error message
                    if (status == STAT_SUCCESS){
                        SET_MSG_RESULT(result, strdup(snmp_errstring(response->errstat)));
                        ret = SYSINFO_RET_FAIL;
                    }            }
                //Free the used structure
                snmp_free_pdu(response);
            }
            else{
                //If the index of the port is 0 then is status is set to UP
                rrpp_struct_set_port_status(PORT_UP, current_port, rrpp_tmp);
            }
            //Set the index of the next port to retrieved
            if(finish){
                if(current_port == RRPP_PRIMARY_PORT){
                    current_port = RRPP_SECONDARY_PORT;
                }
                //When the status of all the primary and the secondary ports have been retrieved
                //the the next ring is load
                else{
                    current_port = RRPP_PRIMARY_PORT;
                    rrpp_tmp = rrpp_tmp->next;
                }
            }
        }
        
        /********************************************************************
         * The last step is to deduce the state of every ring               *
         *******************************************************************/
        rrpp_tmp = rrpp;
        already_written = 0;
        while (rings_enabled && !status && finish && rrpp_tmp!=NULL ){
            if(rrpp_struct_get_port_status(RRPP_PRIMARY_PORT, rrpp_tmp)== PORT_DOWN || rrpp_struct_get_port_status(RRPP_SECONDARY_PORT, rrpp_tmp)==PORT_DOWN){
                if(len_ring_failed + len_too_many<MAX_CHAR_RESULT-already_written){
                    for(i=0;(i<len_ring_failed) && (i + already_written <MAX_CHAR_RESULT);i++){
                        tmp_res[i+already_written] = msg_ring_failed[i];
                    }
                    if(rrpp_tmp->domain<100 && rrpp_tmp->domain>0){
                        msg_buf[0] = ' '; msg_buf[1] = ' ';
                        itoa(rrpp_tmp->domain,msg_buf);
                        tmp_res[pos_domain+already_written] = msg_buf[0];
                        tmp_res[pos_domain+1+already_written] = msg_buf[1];
                    }
                    if(rrpp_tmp->ring<100 && rrpp_tmp->ring>0 ){
                        msg_buf[0] = ' '; msg_buf[1] = ' ';
                        itoa(rrpp_tmp->ring,msg_buf);
                        tmp_res[pos_ring+already_written] = msg_buf[0];
                        tmp_res[pos_ring+1+already_written] = msg_buf[1];
                    }
                    already_written = already_written+i;
                    
                }
                else{
                    for(i=0;(i<len_too_many) && (i + already_written <MAX_CHAR_RESULT);i++){
                        tmp_res[i+already_written] = msg_too_many[i];
                    }
                    already_written = already_written+i-1;
                    finish = 0;
                }
                
            }
            rrpp_tmp = rrpp_tmp->next;
        }
        if(already_written !=0){
            SET_STR_RESULT(result, strdup(tmp_res));
        }
    }
    ret = SYSINFO_RET_OK;
    if(status !=STAT_SUCCESS){
        
        if (status == STAT_TIMEOUT){
            SET_STR_RESULT(result, strdup("Request timeout"));
            ret = SYSINFO_RET_OK;
        }else if(status == STAT_ERR_INIT){
            SET_MSG_RESULT(result, strdup("Error when Initializing SNMP session"));
            ret = SYSINFO_RET_FAIL;
        }
        else{
            SET_MSG_RESULT(result, strdup("Unknown error in SNMP session"));
            ret = SYSINFO_RET_FAIL;
        }
    }
    //Free the aggregation structures
    rrpp_struct_free(rrpp);
    return ret;
}


/******************************************************************************
 *                                                                            *
 * Function: zbx_module_init                                                  *
 *                                                                            *
 * Purpose: the function is called on agent startup                           *
 *          It should be used to call any initialization routines             *
 *                                                                            *
 * Return value: ZBX_MODULE_OK - success                                      *
 *               ZBX_MODULE_FAIL - module initialization failed               *
 *                                                                            *
 * Comment: the module won't be loaded in case of ZBX_MODULE_FAIL             *
 *                                                                            *
 ******************************************************************************/
int	zbx_module_init()
{
    init_snmp("redundantProtocolsMonitoring");
    return ZBX_MODULE_OK;
}

/******************************************************************************
 *                                                                            *
 * Function: zbx_module_uninit                                                *
 *                                                                            *
 * Purpose: the function is called on agent shutdown                          *
 *          It should be used to cleanup used resources if there are any      *
 *                                                                            *
 * Return value: ZBX_MODULE_OK - success                                      *
 *               ZBX_MODULE_FAIL - function failed                            *
 *                                                                            *
 ******************************************************************************/
int	zbx_module_uninit()
{
    return ZBX_MODULE_OK;
}


/******************************************************************************
 *                                                                            *
 * Function: is_valid_ip                                                      *
 *                                                                            *
 * Purpose: Check if the IP address is a valid one                            *
 *                                                                            *
 * Parameters: src - string containing an IP address                          *
 *                                                                            *
 * Return value:    0 - the IP address is valid                               *
 *                  1 - the IP address is invalid                             *
 *                                                                            *
 * Comment: The source code come from the inet_pton4 function                 *
 *          of the inet_pton.c file of glibc                                  *
 ******************************************************************************/
static int is_valid_ip(const char *src)
{
    static const char digits[] = "0123456789";
    int saw_digit, octets, ch;
    unsigned char tmp[INADDRS], *tp;
    
    saw_digit = 0;
    octets = 0;
    tp = tmp;
    *tp = 0;
    while((ch = *src++) != '\0') {
        const char *pch;
        
        if((pch = strchr(digits, ch)) != NULL) {
            unsigned int val = *tp * 10 + (unsigned int)(pch - digits);
            
            if(saw_digit && *tp == 0)
                return (1);
            if(val > 255)
                return (1);
            *tp = (unsigned char)val;
            if(! saw_digit) {
                if(++octets > 4)
                    return (1);
                saw_digit = 1;
            }
        }
        else if(ch == '.' && saw_digit) {
            if(octets == 4)
                return (1);
            *++tp = 0;
            saw_digit = 0;
        }
        else
            return (1);
    }
    if(octets < 4)
        return 1;
    return 0;
}
char* itoa(int i, char b[]){
    char const digit[] = "0123456789";
    char* p = b;
    if(i<0){
        *p++ = '-';
        i *= -1;
    }
    int shifter = i;
    do{ //Move to where representation ends
        ++p;
        shifter = shifter/10;
    }while(shifter);
    do{ //Move back, inserting digits as u go
        *--p = digit[i%10];
        i = i/10;
    }while(i);
    return b;
}
/******************************************************************************
 *                                                                            *
 * Function: snmpbulkget                                                      *
 *                                                                            *
 * Purpose: Do an snmpbulkget request                                         *
 *                                                                            *
 * Parameters: session - an init struct snmp_session                          *
 *             response - a struct snmp_pdu that will contains the response   *
 *                        of the resquest if no failure                       *
 *             id_oid - the oid of the node where to start the request        *
 *             id_len - the lenght of the oid provided                        *
 *             max_repetition - the max repetition of the bulkget request     *
 *                                                                            *
 * Return value:    STAT_SUCCESS - the request was succesfull                 *
 *                  STAT_TIMEOUT - the request timeout                        *
 *                  STAT_ERROR - an error happened during the request         *
 *                  STAT_ERR_INIT - Incorrect initialisation                  *
 *                                                                            *                        *
 ******************************************************************************/
static int snmpbulkget(struct snmp_session session, struct snmp_pdu ** response, oid id_oid[MAX_OID_LEN], size_t id_len,int max_repetition){
    int status;
    struct snmp_session *sess_handle;
    struct snmp_pdu *pdu;
    
    //Init the session
    sess_handle = snmp_open(&session);
    if (!sess_handle) {
        return STAT_ERR_INIT;
    }
    //Create the PDU
    pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
    pdu->errstat = 0;   //Set getbulk non repeater
    pdu->errindex = max_repetition; //Set getbulk max repetition
    snmp_add_null_var(pdu, id_oid, id_len);
    
    //Send request
    status = snmp_synch_response(sess_handle, pdu, response);
    
    //Close session
    snmp_close(sess_handle);
    return status;
}

/******************************************************************************
 *                                                                            *
 * Function: snmpbulkget                                                      *
 *                                                                            *
 * Purpose: Do an snmpget request                                             *
 *                                                                            *
 * Parameters: session - an init struct snmp_session                          *
 *             response - a struct snmp_pdu that will contains the response   *
 *                        of the resquest if no failure                       *
 *             id_oid - the oid of the node to request                        *
 *             id_len - the lenght of the oid provided                        *
 *                                                                            *
 * Return value:    STAT_SUCCESS - the request was succesfull                 *
 *                  STAT_TIMEOUT - the request timeout                        *
 *                  STAT_ERROR - an error happened during the request         *
 *                  STAT_ERR_INIT - Incorrect initialisation                  *
 *                                                                            *
 ******************************************************************************/
static int snmpget(struct snmp_session session, struct snmp_pdu ** response,oid id_oid[MAX_OID_LEN], size_t id_len){
    int status;
    struct snmp_session *sess_handle;
    struct snmp_pdu *pdu;
    
    //Init the session
    sess_handle = snmp_open(&session);
    if (!sess_handle) {
        return STAT_ERR_INIT;
    }
    
    //Create the PDU
    pdu = snmp_pdu_create(SNMP_MSG_GET);
    snmp_add_null_var(pdu, id_oid, id_len);
    //Send request
    status = snmp_synch_response(sess_handle, pdu, response);
    
    //Close session
    snmp_close(sess_handle);
    return status;
}


/******************************************************************************
 *                                                                            *
 * Function: agg_struct_new                                                   *
 *                                                                            *
 * Purpose: Allocate a new agg_struct_t                                       *
 *                                                                            *
 * Parameters: agg - A pointer of an agg_struct_t pointer                     *
 *                                                                            *
 ******************************************************************************/
static void agg_struct_new(agg_struct_t ** agg){
    if(agg!=NULL)*agg = (agg_struct_t *)malloc(sizeof(agg_struct_t));
}

/******************************************************************************
 *                                                                            *
 * Function: agg_struct_free                                                  *
 *                                                                            *
 * Purpose: Free aa agg_struct_t with all the next dependencies               *
 *                                                                            *
 * Parameters: agg - An agg_struct_t pointer                                  *
 *                                                                            *
 ******************************************************************************/
static void agg_struct_free(agg_struct_t *agg){
    agg_struct_t * current = agg;
    agg_struct_t * next;
    //Free all the structure by browsing through them
    if(agg!=NULL){
        while (current !=NULL) {
            next = current->next;
            free(current);
            current = next;
        }
    }
}

/******************************************************************************
 *                                                                            *
 * Function: agg_struct_init                                                  *
 *                                                                            *
 * Purpose: Init an agg_struct_t                                              *
 *                                                                            *
 * Parameters:  index - the index value to initialise the struct with         *
 *              agg - An agg_struct_t pointer                                 *
 *                                                                            *
 ******************************************************************************/
static void agg_struct_init(long index, agg_struct_t *agg){
    if(agg!=NULL){
        agg->index = index;
        agg->next = NULL;
        agg->nb_ports = 0;
        agg->status = AGG_STATUS_UNKNOWN;
    }
}

/******************************************************************************
 *                                                                            *
 * Function: agg_struct_exist                                                 *
 *                                                                            *
 * Purpose: Retrieve a struct node in the list with a specific index value    *
 *                                                                            *
 * Parameters:  index - the index value of the aggregation                    *
 *              agg - An agg_struct_t pointer                                 *
 *                                                                            *
 * Return value:    the address of the node if found                          *
 *                  NULL otherwise                                            *
 ******************************************************************************/
static agg_struct_t * agg_struct_exist(long index,agg_struct_t * agg){
    agg_struct_t *n = agg;
    while(n != NULL){
        if(n->index == index)return n;
        n = n->next;
    }
    return NULL;
}

/******************************************************************************
 *                                                                            *
 * Function: agg_struct_add                                                   *
 *                                                                            *
 * Purpose: Add a struct node at the end of the list with a index value       *
 *                                                                            *
 * Parameters:  index - the index value to initialise the new struct with     *
 *              agg - An agg_struct_t pointer                                 *
 *                                                                            *
 ******************************************************************************/
static agg_struct_t * agg_struct_add(long index, agg_struct_t ** agg){
    agg_struct_t *n = *agg;
    agg_struct_t * new;
    agg_struct_new(&new);
    agg_struct_init(index, new);
    if(*agg==NULL)*agg = new;
    else{
        while (n->next !=NULL) n = n->next;
        n->next = new;
    }
    return new;
}

/******************************************************************************
 *                                                                            *
 * Function: agg_struct_add_port                                              *
 *                                                                            *
 * Purpose: Add a port in the aggregation structure                           *
 *                                                                            *
 * Parameters:  port_index - the index of the port to add                     *
 *              agg - An agg_struct_t pointer                                 *
 *                                                                            *
 ******************************************************************************/
static void agg_struct_add_port(long port_index,agg_struct_t *agg){
    if(agg!=NULL && agg->nb_ports<MAX_PORT_AGG){
        agg->ports[agg->nb_ports] = port_index;
        agg->nb_ports ++;
    }
}

/******************************************************************************
 *                                                                            *
 * Function: rrpp_struct_new                                                  *
 *                                                                            *
 * Purpose: Allocate a new rrpp_struct_t                                      *
 *                                                                            *
 * Parameters: rppp - A pointer of an rrpp_struct_t pointer                   *
 *                                                                            *
 ******************************************************************************/
static void rrpp_struct_new(rrpp_struct_t ** rrpp){
    if(rrpp !=NULL) *rrpp = (rrpp_struct_t *)malloc(sizeof(rrpp_struct_t));
}

/******************************************************************************
 *                                                                            *
 * Function: rrpp_struct_free                                                 *
 *                                                                            *
 * Purpose: Free aa rrpp_struct_t with all the next dependencies              *
 *                                                                            *
 * Parameters: rrpp - An rrpp_struct_t pointer                                *
 *                                                                            *
 ******************************************************************************/
static void rrpp_struct_free(rrpp_struct_t *rrpp){
    rrpp_struct_t * current = rrpp;
    rrpp_struct_t * next;
    //Free all the structure by browsing through them
    if(rrpp!=NULL){
        while (current !=NULL) {
            next = current->next;
            free(current);
            current = next;
        }
    }
}

/******************************************************************************
 *                                                                            *
 * Function: rrpp_struct_init                                                 *
 *                                                                            *
 * Purpose: Init an rrpp_struct_t                                             *
 *                                                                            *
 * Parameters:  domain - the domain ip of the rrpp ring                       *
 *              ring - the ring id of the rrpp ring                           *
 *              rrpp - An rrpp_struct_t pointer                               *
 *                                                                            *
 ******************************************************************************/
static void rrpp_struct_init(short domain, short ring,rrpp_struct_t *rrpp){
    if(rrpp !=NULL){
        rrpp->next = NULL;
        rrpp->domain = domain;
        rrpp->ring = ring;
        rrpp->primary_port = 0;
        rrpp->secondary_port = 0;
        rrpp->primary_port_status = RRPP_UNKNOWN;
        rrpp->secondary_port_status = RRPP_UNKNOWN;
    }
}

/******************************************************************************
 *                                                                            *
 * Function: rrpp_struct_exist                                                *
 *                                                                            *
 * Purpose: Retrieve a struct node in the list with a specific index value    *
 *                                                                            *
 * Parameters:  domain - the domain ip of the rrpp ring                       *
 *              ring - the ring id of the rrpp ring                           *
 *              rrpp - An rrpp_struct_t pointer                               *
 *                                                                            *
 * Return value:    the address of the node if found                          *
 *                  NULL otherwise                                            *
 ******************************************************************************/
static rrpp_struct_t * rrpp_struct_exist(short domain,short ring,rrpp_struct_t * rrpp){
    rrpp_struct_t *n = rrpp;
    while(n != NULL){
        if(n->domain == domain && n->ring == ring)return n;
        n = n->next;
    }
    return NULL;
}

/******************************************************************************
 *                                                                            *
 * Function: rrpp_struct_add                                                  *
 *                                                                            *
 * Purpose: Add a struct node at the end of the list with a index value       *
 *                                                                            *
 * Parameters:  domain - the domain ip of the rrpp ring                       *
 *              ring - the ring id of the rrpp ring                           *
 *              rrpp - An rrpp_struct_t pointer                               *
 *                                                                            *
 ******************************************************************************/
static rrpp_struct_t * rrpp_struct_add(short domain, short ring, rrpp_struct_t ** rrpp){
    rrpp_struct_t *n = *rrpp;
    rrpp_struct_t * new;
    rrpp_struct_new(&new);
    rrpp_struct_init(domain,ring, new);
    if(*rrpp==NULL)*rrpp = new;
    else{
        while (n->next !=NULL) n = n->next;
        n->next = new;
    }
    return new;
}


/******************************************************************************
 *                                                                            *
 * Function: rrpp_struct_set_port                                             *
 *                                                                            *
 * Purpose: Set the index of a port (primary or secondary) in the rrpp        *
 *          structure                                                         *
 *                                                                            *
 * Parameters:  port_index - the index of the port                            *
 *              selected_port - the port(primary or secondary) to set         *
 *              rrpp - An rrpp_struct_t pointer                               *
 *                                                                            *
 ******************************************************************************/
static void rrpp_struct_set_port(long port_index, short selected_port, rrpp_struct_t *rrpp){
    if(rrpp !=NULL){
        if(selected_port == RRPP_PRIMARY_PORT){
            rrpp->primary_port = port_index;
        }
        if(selected_port == RRPP_SECONDARY_PORT){
            rrpp->secondary_port = port_index;
        }
    }
}

/******************************************************************************
 *                                                                            *
 * Function: rrpp_struct_get_port                                             *
 *                                                                            *
 * Purpose: Get the index of a port (primary or secondary) in the rrpp        *
 *          structure                                                         *
 *                                                                            *
 * Parameters:  selected_port - the port(primary or secondary) to get         *
 *              rrpp - An rrpp_struct_t pointer                               *
 *                                                                            *
 ******************************************************************************/
static long rrpp_struct_get_port(short selected_port, rrpp_struct_t *rrpp){
    if(rrpp !=NULL){
        if(selected_port == RRPP_PRIMARY_PORT){
            return rrpp->primary_port;
        }
        if(selected_port == RRPP_SECONDARY_PORT){
            return rrpp->secondary_port;
        }
    }
    return 0;
}

/******************************************************************************
 *                                                                            *
 * Function: rrpp_struct_set_port_status                                      *
 *                                                                            *
 * Purpose: Set the status of a port (primary or secondary) in the rrpp       *
 *          structure                                                         *
 *                                                                            *
 * Parameters:  port_status - the index of the port                           *
 *              selected_port - the port(primary or secondary) to set         *
 *              rrpp - An rrpp_struct_t pointer                               *
 *                                                                            *
 ******************************************************************************/
static void rrpp_struct_set_port_status(short port_status, short selected_port, rrpp_struct_t *rrpp){
    if(rrpp !=NULL){
        if(selected_port == RRPP_PRIMARY_PORT){
            rrpp->primary_port_status = port_status;
        }
        if(selected_port == RRPP_SECONDARY_PORT){
            rrpp->secondary_port_status = port_status;
        }
    }
}

/******************************************************************************
 *                                                                            *
 * Function: rrpp_struct_get_port                                             *
 *                                                                            *
 * Purpose: Get the status of a port (primary or secondary) in the rrpp       *
 *          structure                                                         *
 *                                                                            *
 * Parameters:  selected_port - the port(primary or secondary) to Get         *
 *              rrpp - An rrpp_struct_t pointer                               *
 *                                                                            *
 ******************************************************************************/
static short rrpp_struct_get_port_status(short selected_port, rrpp_struct_t *rrpp){
    if(rrpp !=NULL){
        if(selected_port == RRPP_PRIMARY_PORT){
            return rrpp->primary_port_status;
        }
        if(selected_port == RRPP_SECONDARY_PORT){
            return rrpp->secondary_port_status;
        }
    }
    return RRPP_UNKNOWN;
}

