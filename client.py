import socket
import sys
import re
from shared import errorFound, decodeResponse, createQuery

# CONSTANTS
DNS_RECORD_TYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX"}
OP_CODE = {0: "QUERY", 1: "REPLY"}
RCODE = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

def queryResolver(domainName, host, port, timeout, queryType):
    # create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # UDP
    sock.settimeout(timeout)
    sock.connect((host, port))

    # construct DNS query
    query = createQuery(domainName, queryType)
    # send query
    sock.sendall(query)
    data = None

    # wait for response from resolver
    while data == None:
        try:
            data = sock.recv(1024)
        except socket.timeout:
            errorFound("Client Timeout")

    # recieve response from resolver
    sock.close()
    return data

def main():
    #check number of command line args
    if len(sys.argv) < 5:
        errorFound("Invalid arguments\nUsage: client resolver_ip resolver_port name type [timeout=5]")
    
    # take in command line args
    resolverIP = sys.argv[1]
    try:
        resolverPort = int(sys.argv[2])
    except ValueError:
        errorFound("Invalid arguments\nUsage: client resolver_ip resolver_port name type [timeout=5]")
    domainName = sys.argv[3]
    queryType = sys.argv[4].upper()
    timeout = 5

    #check query type
    if queryType not in DNS_RECORD_TYPES.values():
        errorFound("Invalid arguments\nUsage: client resolver_ip resolver_port name type [timeout=5]")

    if queryType == "PTR":
        # check domain IP 
        if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domainName) == None:
            errorFound("Invalid arguments\nUsage: client resolver_ip resolver_port name type [timeout=5]")
        #change from a.b.c.d form to d.c.b.a.in-addr.arpa form
        ipParts = domainName.split(".")
        ipParts.reverse()
        domainName = '.'.join(ipParts)
        domainName += ".in-addr.arpa"
    else:
        # check domain name (only allow alphanumeric characters, hyphens and dots)
        if re.match(r"[^A-Za-z0-9\-\.]", domainName):
            errorFound("Invalid arguments\nUsage: client resolver_ip resolver_port name type [timeout=5]")

    # check resolverIP 
    if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", resolverIP) == None:
        errorFound("Invalid arguments\nUsage: client resolver_ip resolver_port name type [timeout=5]")

    # check resolver port is in between (1024-65535) inclusive
    if resolverPort not in range(1024, 65536):
        errorFound("Invalid arguments\nUsage: client resolver_ip resolver_port name type [timeout=5]")

    if len(sys.argv) == 6:
        timeout = sys.argv[5]
        try:
            timeout = float(timeout)
        except ValueError:
            errorFound("Invalid arguments\nUsage: client resolver_ip resolver_port name type [timeout=5]")
    if timeout <= 0:
        errorFound("Invalid arguments\nUsage: client resolver_ip resolver_port name type [timeout=5]")
    # intiate query to resolver
    response = queryResolver(domainName, resolverIP, resolverPort, timeout, list(DNS_RECORD_TYPES.keys())[list(DNS_RECORD_TYPES.values()).index(queryType)])
    results = decodeResponse(response)

    # handle returned error codes
    if "Timeout" in results.keys():
        errorFound("Server Timeout")
    elif results["header"]["rcode"] != 0:
        if results["header"]["rcode"] == 1:
            #format error
            errorFound("Invalid DNS query format")
        elif results["header"]["rcode"] == 2:
            # Server Error
            errorFound(f"Unable to connect to {domainName}")
        elif results["header"]["rcode"] == 3:
            # Name Error
            errorFound(f"Server can't find {domainName}")
        else:
            # Other errors 
            errorFound(f"{results['header']['rcode']}")
    # display results
    print(";; Got answer:")
    print(f";; ->>HEADER<<- opcode: {OP_CODE[results['header']['opcode']]}, status: {RCODE[results['header']['rcode']]}, id: {results['header']['id']}")
    print(f";; FLAGS: {'aa ' if results['header']['aa'] else ''} {'tr ' if results['header']['tc'] else ''}; QUERY:{results['header']['qst']}, ANSWER:{results['header']['ans']}\n")
    print(";; QUESTION SECTION")
    print(f";{domainName}           IN    {queryType}\n")

    print(";; ANSWER SECTION:")
    for i in range(len(results['data'])):
        print(f"{results['data'][i]['name']}    {results['data'][i]['ttl']}    IN    {DNS_RECORD_TYPES[results['data'][i]['ansType']]}    {results['data'][i]['data']}")

if __name__ == "__main__":
    main()
