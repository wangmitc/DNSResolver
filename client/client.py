from socket import *
import pickle
import sys
import re
import random
import struct

def errorFound(message):
    print(f"Error: {message}")
    exit()

def formatDomain(domainName):
    dnsQuery = b''
    for domainPart in domainName.split("."):
        dnsQuery += struct.pack("!B", len(domainPart))
        for character in domainPart:
            dnsQuery += struct.pack("!c", character.encode('utf-8'))
    dnsQuery += struct.pack('!b', 0)
    return dnsQuery


def createQuery(domainName):
    query_id = random.randint(0, 65535)
    flags = 0
    qst = 1
    ans = 0
    auth = 0
    add = 0

    # DNS header
    dnsHeader = struct.pack("!HHHHHH", query_id, 0, qst, ans, auth, add)
    #DNS question
    dnsQuestion = formatDomain(domainName)
    dnsQuestion += struct.pack('!HH', 1, 1)
    return dnsHeader + dnsQuestion



def queryResolver(domainName, host, port):
    # create socket
    sock = socket(AF_INET, SOCK_STREAM) # UDP
    sock.settimeout(30)
    sock.connect((host, port))

    # construct DNS query
    queryData = createQuery(domainName)
    #query = {"name":domainName,"type":"A", "class": "IN"}
    # queryData = pickle.dumps(query)
    query = {"queryName": formatDomain(domainName), "data": queryData}
    # send query
    # sock.sendall(queryData)
    sock.sendall(pickle.dumps(query))
    data = None

    # wait for response from resolver
    while data == None:
        try:
            data = sock.recv(1024)
            response = data.decode()
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
    # print(f";; FLAGS: {'aa ' if results['aa'] else ''} {'tr ' if results['tr'] else ''}\n")
    # print(";; QUESTION SECTION")
    # print(results['question'] + "\n")
    # print(";; ANSWER SECTION:")
    # print(results['answer'])

if __name__ == "__main__":
    main()
