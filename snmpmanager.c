#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#define DEBUG true

const char *system_oid = "1.3.6.1.2.1.1";
const char *sysDescr_oid = "1.3.6.1.2.1.1.1.0";
const char *ifDescr_oid = "1.3.6.1.2.1.2.2.1.2";
const char *ifAddr_oid = "1.3.6.1.2.1.4.20.1.1";
const char *ifIn_oid = "1.3.6.1.2.1.2.2.1.10";
const char *ifOut_oid = "1.3.6.1.2.1.2.2.1.16";
const char *ifNet_oid = "1.3.6.1.2.1.4.22.1.3";
const char *sysUpTime_oid = "1.3.6.1.2.1.1.3.0";

netsnmp_pdu *snmp_walk(netsnmp_session *open_session, char *oid);

int main(int argc, char **argv) {
    // Get input for sample time interval, # of samples, agent ip, community name
    int sample_interval, num_samples;
    char *agent_ip, *community;
    if (DEBUG) {
        agent_ip = "127.0.0.1";
        community = "local";
    } else {
        printf("Enter a time interval: ");
        scanf("%d", &sample_interval);
        printf("Enter a number of samples: ");
        scanf("%d", &num_samples);
        printf("Enter the SNMP agent's IP: ");
        scanf("%s", agent_ip);
        printf("Enter the community name: ");
        scanf("%s", community);
    };

    netsnmp_session session, *ss;
    netsnmp_pdu *pdu;
    netsnmp_pdu *response;

    oid anOID[MAX_OID_LEN];
    size_t anOID_len;

    netsnmp_variable_list *vars;
    int status;
    int count = 1;

    // Initialize the SNMP library
    init_snmp("snmpmanager");

    // Initialize a "session" that defines who we're going to talk to
    snmp_sess_init(&session);                   /* set up defaults */
    session.peername = strdup(agent_ip);

    // set the SNMP version number
    session.version = SNMP_VERSION_2c;

    // set the SNMPv1 community name used for authentication
    session.community = community;
    session.community_len = strlen(session.community);

    // Open the session
    SOCK_STARTUP;
    ss = snmp_open(&session);

    if (!ss) {
        snmp_sess_perror("ack", &session);
        SOCK_CLEANUP;
        exit(1);
    }

    // Create the PDU for the data for our request.
    pdu = snmp_pdu_create(SNMP_MSG_GET);
    anOID_len = MAX_OID_LEN;
    if (!snmp_parse_oid(".1.3.6.1.2.1.2.1.0", anOID, &anOID_len)) {
        snmp_perror(".1.3.6.1.2.1.1.1.0");
        SOCK_CLEANUP;
        exit(1);
    }

    snmp_add_null_var(pdu, anOID, anOID_len);

    // Send the Request out.
    response = snmp_walk(ss, ifDescr_oid);

    // Print the result variable
    printf("Interfaces: \n");
    for (vars = response->variables; vars; vars = vars->next_variable) {
        print_variable(vars->name, vars->name_length, vars);
    }

    /*
     * Clean up:
     *  1) free the response.
     *  2) close the session.
     */
    if (response)
        snmp_free_pdu(response);
    snmp_close(ss);

    SOCK_CLEANUP;
    return (0);
}

netsnmp_pdu* snmp_walk(netsnmp_session *open_session, char *first_oid) {
    // Create the pdu for the request
    netsnmp_pdu *pdu;
    oid anOID[MAX_OID_LEN];
    size_t anOID_len = MAX_OID_LEN;
    pdu = snmp_pdu_create(SNMP_MSG_GET);
    if (!snmp_parse_oid(first_oid, anOID, &anOID_len)) {
        snmp_perror(first_oid);
        SOCK_CLEANUP;
        exit(1);
    }

    snmp_add_null_var(pdu, anOID, anOID_len);

    // Send the Request out.
    int status = netsnmp_query_walk(pdu->variables, open_session);

    // Process the response
    if (status == STAT_SUCCESS && pdu->variables) {
        // SUCCESS: Return the result pdu
        return pdu;
    } else {
        // FAILURE: Print what went wrong
        if (status == STAT_SUCCESS)
            fprintf(stderr, "Error in packet\nReason: %s\n", snmp_errstring(pdu->errstat));
        else if (status == STAT_TIMEOUT)
            fprintf(stderr, "Timeout: No response from %s.\n", open_session->peername);
        else
            snmp_sess_perror("snmpmanager", open_session);
        return NULL;
    }
}

