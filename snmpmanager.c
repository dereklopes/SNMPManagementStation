#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/types.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#define DEBUG true

const char *system_oid = "1.3.6.1.2.1.1";
const char *sysDescr_oid = "1.3.6.1.2.1.1.1.0";
const char *ifDescr_oid = "1.3.6.1.2.1.2.2.1.2";
const char *ifAddr_oid = "1.3.6.1.2.1.4.20.1.1";
const char *ifIn_oid = "1.3.6.1.2.1.2.2.1.10";
const char *ifOut_oid = "1.3.6.1.2.1.2.2.1.16";
const char *ifNet_oid = "1.3.6.1.2.1.4.22.1.3";
const char *sysUpTime_oid = "1.3.6.1.2.1.1.3.0";

netsnmp_pdu *snmp_walk(netsnmp_session *open_session, char *first_oid);
char **getVariablesAsStr(netsnmp_pdu *pdu, int *count);
int *getTrafficFromPDU(netsnmp_pdu *pdu, int if_count);

int main(int argc, char **argv) {
    // Get input for sample time interval, # of samples, agent ip, community name
    unsigned int sample_interval, num_samples;
    char *agent_ip, *community;
    if (DEBUG) {
        agent_ip = "127.0.0.1";
        community = "local";
        sample_interval = 1;
        num_samples = 3;
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

    // Initialize the SNMP library
    init_snmp("snmpmanager");

    // Initialize a "session" that defines who we're going to talk to
    snmp_sess_init(&session);
    session.peername = strdup(agent_ip);

    // set SNMP information
    session.version = SNMP_VERSION_2c;
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

    // Get Interfaces
    netsnmp_pdu *ifNamesPDU = snmp_walk(ss, ifDescr_oid);
    netsnmp_pdu *ifAddressesPDU = snmp_walk(ss, ifAddr_oid);
    int if_count;
    char **ifNames = getVariablesAsStr(ifNamesPDU, &if_count);
    char **ifAddresses = getVariablesAsStr(ifAddressesPDU, &if_count);
    printf("|------------------------------------------------------------------------------\n");
    printf("| Interfaces:\n");
    for (int i = 0; i < if_count; i++) {
        printf("| %d | %s | %s\n", i, ifNames[i], ifAddresses[i]);
    }
    printf("|------------------------------------------------------------------------------\n");

    // Get IP Neighbors
    netsnmp_pdu *ipNeighborsPDU = snmp_walk(ss, ifNet_oid);
    int neighbors_count;
    char **neighbors = getVariablesAsStr(ipNeighborsPDU, &neighbors_count);
    printf("|------------------------------------------------------------------------------\n");
    printf("| Neighbors:\n");
    for (int i = 0; i < neighbors_count; i++) {
        printf("| %d | %s\n", i, neighbors[i]);
    }
    printf("|------------------------------------------------------------------------------\n");

    // Get traffic
    int **in_traffic = (int**) malloc(if_count * num_samples * sizeof(in_traffic));
    int **out_traffic = (int**) malloc(if_count * num_samples * sizeof(out_traffic));
    printf("Gathering traffic information for %d seconds...\n", sample_interval * num_samples);
    for (int i = 0; i < num_samples; i++) {
        in_traffic[i] = getTrafficFromPDU(snmp_walk(ss, ifIn_oid), if_count);
        out_traffic[i] = getTrafficFromPDU(snmp_walk(ss, ifOut_oid), if_count);
        if (DEBUG)
            printf("In: %d | Out: %d\n", *in_traffic[i], *out_traffic[i]);
        sleep(sample_interval);
    }


    // Clean up and close the session
    snmp_free_pdu(ifNamesPDU);
    snmp_free_pdu(ifAddressesPDU);
    snmp_free_pdu(ipNeighborsPDU);
    free(ifNames);
    free(ifAddresses);
    free(neighbors);
    snmp_close(ss);
    SOCK_CLEANUP;
    return (0);
}

netsnmp_pdu *snmp_walk(netsnmp_session *open_session, char *first_oid) {
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

char **getVariablesAsStr(netsnmp_pdu *pdu, int *count) {
    *count = 0;
    netsnmp_variable_list *vars;
    for (vars = pdu->variables; vars; vars = vars->next_variable) {
        (*count)++;
    }
    char **values = (char**) malloc(sizeof(char*) * *count);
    vars = pdu->variables;
    for (int i = 0; i < *count; i++) {
        if (vars->type == ASN_IPADDRESS) {
            char *ip = (char*) malloc(16);
            u_char *oct = vars->val.bitstring;
            snprintf(ip, 16, "%d.%d.%d.%d", oct[0], oct[1], oct[2], oct[3]);
            values[i] = ip;
        } else if (vars->type == ASN_COUNTER) {
            long* value = vars->val.integer;
            sprintf(values[i], "%ld", *value);
            printf("%s\n", values[i]);
            fflush(stdout);
        } else {
            values[i] = vars->val.string;
            vars = vars->next_variable;
        }
    }
    return values;
}

int *getTrafficFromPDU(netsnmp_pdu *pdu, int if_count) {
    int count = 0;
    netsnmp_variable_list *vars;
    int *values = (int*) malloc(if_count * sizeof(values));

    for (vars = pdu->variables; vars; vars = vars->next_variable) {
        if (vars->type == ASN_COUNTER) {
            values[count++] = (int) *vars->val.integer;
        } else {
            printf("PDU is not a counter\n");
        }
    }

    return values;
}
