from socket import *
import pickle
import sys
import re

def errorFound(message):
    print(f"Error: {message}")
    exit()

def queryResolver(domainName, host, port):
    # create socket
    sock = socket(AF_INET, SOCK_STREAM) # UDP
    sock.settimeout(2)
    sock.connect((host, port))

    # construct DNS query
    query = {"name":domainName,"type":"A", "class": "IN"}
    queryData = pickle.dumps(query)

    # send query
    sock.sendall(queryData)
    data = None

    # wait for response from resolver
    while data == None:
        try:
            data = sock.recv(1024)
            response = pickle.loads(data)
        except timeout:
            break

    # recieve response from resolver
    sock.close()
    return response

def main():
    #check number of command line args
    if len(sys.argv) < 4:
        errorFound("Invalid arguments\nUsage: client resolver_ip resolver_port name")
    
    # take in command line args
    resolverIP = sys.argv[1]
    resolverPort = int(sys.argv[2])
    domainName = sys.argv[3]

    # check domain name (only allow alphanumeric characters, hyphens and dots)
    if re.match(r"[^A-Za-z0-9\-\.]", domainName):
        errorFound("Invalid arguments\nUsage: client resolver_ip resolver_port name")

    # check resolverIP 
    if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", resolverIP) == None:
        errorFound("Invalid arguments\nUsage: client resolver_ip resolver_port name")

    # check resolver port is in between (1024-65535) inclusive
    if resolverPort not in range(1024, 65536):
        errorFound("Invalid arguments\nUsage: client resolver_ip resolver_port name")
    
    # intiate query to resolver
    results = queryResolver(domainName, resolverIP, resolverPort)

    # display results
    print(f";; FLAGS: {'aa ' if results['aa'] else ''} {'tr ' if results['tr'] else ''}\n")
    print(";; QUESTION SECTION")
    print(results['question'] + "\n")
    print(";; ANSWER SECTION:")
    print(results['answer'])

if __name__ == "__main__":
    main()
