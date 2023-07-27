import socket
import pickle
import sys
import re
import random
import struct
from shared import errorFound, formatDomain, decodeResponse

# constants
DNS_RECORD_TYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX"}

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
            data = sock.recv(2048)
            # response = pickle.loads(data)
        except socket.timeout:
            errorFound("Client Timeout")

    # recieve response from resolver
    sock.close()
    return data

# def decodeResponse(response, queryName):
#     #unpack the header
#     header = struct.unpack_from(">HHHHHH", response, 0)
#     msgHeader = {}
#     #MessageID
#     msgHeader["id"] = header[0]
#     # flags
#     flags = header[1]
#     #use masks and bit shifts to extract each flag (bit 0 to 15)
#     # qr (0th bit in flags)
#     msgHeader["id"] = flags >> 15
#     # opcode (1-4th bits in flags)
#     msgHeader["opcode"] = (flags & 0x7800) >> 11
#     # aa (5th bit in flags)
#     msgHeader["aa"] = (flags & 0x0400) >> 10
#     # tc (6th bit in flags)
#     msgHeader["tc"] = (flags & 0x0200) >> 9
#     # rd (7th bit in flags)
#     msgHeader["rd"] = (flags & 0x0100) >> 8
#     # ra (8th bit in flags)
#     msgHeader["ra"] = (flags & 0x0080) >> 7
#     # (Note: reserved field is 9-11th bits. not needed)
#     # rcode (12-15th bits in flags) 
#     msgHeader["rcode"] = (flags & 0x000f)

#     # number of entries in each section
#     qst = header[2]
#     msgHeader["qst"] = qst

#     ans = header[3]
#     msgHeader["ans"] = ans

#     auth = header[4]
#     msgHeader["auth"] = auth

#     add = header[5]
#     msgHeader["add"] = add
#     #skip question name
#     offset = 16 + len(queryName)
    
#     #unpack the authority section data
#     answers = []
#     count = ans if ans > 0 else auth
#     for i in range(count):
#         # get name
#         name = decodeName(response, offset)
#         offset += name["length"]

#         #get answer fields
#         ansFields = struct.unpack_from(">HHIH", response, offset)
#         ansType = ansFields[0]
#         ansClass = ansFields[1]
#         ttl = ansFields[2]
#         rdLength = ansFields[3]
#         offset += 10
#         print(ansType)
#         if ansType == 1:
#             # Type A: get ip
#             ip = {"name": name['name'], "ansType": ansType, "ansClass": ansClass, "ttl": ttl, "rdLength": rdLength, "data": decodeIP(response, offset, rdLength)}
#             answers.append(ip)
#         elif ansType == 2 or ansType == 5:
#             # Type NS and CNAME: get name server
#             nameServer = {"name": name['name'], "ansType": ansType, "ansClass": ansClass, "ttl": ttl, "rdLength": rdLength, "data": decodeName(response, offset)["name"]}
#             answers.append(nameServer)
#         offset += rdLength
    
#     # filter out duplicate answers
#     answers = [dict(tAns) for tAns in {tuple(ans.items()) for ans in answers}]
#     msg = {"header": msgHeader, "data": answers}
#     return msg

def main():
    #check number of command line args
    if len(sys.argv) < 4:
        errorFound("Invalid arguments\nUsage: client resolver_ip resolver_port name [timeout=5]")
    
    # take in command line args
    resolverIP = sys.argv[1]
    try:
        resolverPort = int(sys.argv[2])
    except ValueError:
        errorFound("Invalid arguments\nUsage: client resolver_ip resolver_port name [timeout=5]")
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
    response = queryResolver(domainName, resolverIP, resolverPort, timeout)
    results = decodeResponse(response, formatDomain(domainName))
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
