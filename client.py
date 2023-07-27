import socket
import pickle
import sys
import re
import random
import struct

# constants
DNS_RECORD_TYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX"}


def errorFound(message):
    print(f"Error: {message}")
    exit()

def queryResolver(domainName, host, port, timeout):
    # create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # UDP
    print(timeout)
    sock.settimeout(timeout)
    sock.connect((host, port))

    # construct DNS query
    query = {"domain": domainName, "type": 1}
    # send query
    sock.sendall(pickle.dumps(query))
    data = None

    # wait for response from resolver
    while data == None:
        try:
            data = sock.recv(1024)
            response = pickle.loads(data)
        except socket.timeout:
            errorFound("Client Timeout")

    # recieve response from resolver
    sock.close()
    return response

def main():
    #check number of command line args
    if len(sys.argv) < 4:
        errorFound("Invalid arguments\nUsage: client resolver_ip resolver_port name [timeout=5]")
    
    # take in command line args
    resolverIP = sys.argv[1]
    resolverPort = int(sys.argv[2])
    domainName = sys.argv[3]
    timeout = 5
    # check domain name (only allow alphanumeric characters, hyphens and dots)
    if re.match(r"[^A-Za-z0-9\-\.]", domainName):
        errorFound("Invalid arguments\nUsage: client resolver_ip resolver_port name [timeout=5]")

    # check resolverIP 
    if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", resolverIP) == None:
        errorFound("Invalid arguments\nUsage: client resolver_ip resolver_port name [timeout=5]")

    # check resolver port is in between (1024-65535) inclusive
    if resolverPort not in range(1024, 65536):
        errorFound("Invalid arguments\nUsage: client resolver_ip resolver_port name [timeout=5]")
    
    if len(sys.argv) == 5:
        timeout = sys.argv[4]
        try:
            timeout = float(timeout)
        except ValueError:
            errorFound("Invalid arguments\nUsage: client resolver_ip resolver_port name [timeout=5]")
    
    # intiate query to resolver
    results = queryResolver(domainName, resolverIP, resolverPort, timeout)
    print(results)

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
    print(f";; ->>HEADER<<- opcode: {results['header']['opcode']}")
    print(f";; FLAGS: {'aa ' if results['header']['aa'] else ''} {'tr ' if results['header']['tc'] else ''}\n")
    print(";; QUESTION SECTION")
    print(f";{results['data'][0]['name']} {DNS_RECORD_TYPES[results['data'][0]['ansType']]} IN\n")

    print(";; ANSWER SECTION:")
    for i in range(len(results['data'])):
        print(results['data'][i]['data'])

if __name__ == "__main__":
    main()
