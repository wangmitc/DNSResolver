import socket
import pickle
import sys
import re
import struct
import random

def errorFound(message):
    print(f"Error: {message}")
    exit()

def readHints():
    rootNamesToIp = {}

    #read in root hints file
    with open("named.root", "r") as hintsFile:
        currRootName = ""
        for line in hintsFile.readlines():
            # if shows name server
            if re.search(r"^\.", line):
                # get name of server
                currRootName = re.split(' +', line)[3].strip()
            elif currRootName != "" and line.startswith(currRootName):
                # add to dict
                rootNamesToIp[currRootName] = re.split(' +', line)[3].strip()
                # stops from getting IPv6
                currRootName = ""
    return rootNamesToIp

def decodeIP(response, offset, rdLength):

    #get chars of the ip
    ipChars = struct.unpack_from(f">{'B' * rdLength}", response, offset)

    # format the ip
    ip = ""
    for char in ipChars:
        ip += f"{str(char)}."
    return ip[:-1]

def decodeName(response, offset):
    nameChars = []
    char = None
    isPointer = False

    # get all char for name, until null terminator
    while (char := struct.unpack_from(f">B", response, offset)[0]) != 0:
        # check if name field is pointer (first two bytes are 1)
        if char >= 192:
            # go to pointer address
            # (char << 8) >= 0b1100000000000000
            # offset = char << 8 + (next pointer bit) - 0b1100000000000000 - 1
            offset = (char + struct.unpack_from(">B", response, offset + 1)[0] - 0xc0) - 1
            isPointer = True
        else:
            nameChars.append(char)
        offset += 1
    
    # reformat the name
    name = ""
    partLen = 0
    for char in nameChars:
        if partLen <= 0:
            # get length of name part
            partLen = int(char)
            name += "."
        else:
            # append charcter
            name += chr(int(char))
            partLen -= 1
    name += "."

    # name section olength is variable as it is could be a pointer (2 bytes) or full domain name (variable bytes)
    return {"name": name[1:], "length": (len(nameChars) + 1) if not isPointer else 2}

def decodeResponse(response, queryName, queryType, timeout):
    #unpack the header
    header = struct.unpack_from(">HHHHHH", response, 0)
    msgHeader = {}
    #MessageID
    msgHeader["id"] = header[0]
    # flags
    flags = header[1]
    #use masks and bit shifts to extract each flag (bit 0 to 15)
    # qr (0th bit in flags)
    msgHeader["id"] = flags >> 15
    # opcode (1-4th bits in flags)
    msgHeader["opcode"] = (flags & 0x7800) >> 11
    # aa (5th bit in flags)
    msgHeader["aa"] = (flags & 0x0400) >> 10
    # tc (6th bit in flags)
    msgHeader["tc"] = (flags & 0x0200) >> 9
    # rd (7th bit in flags)
    msgHeader["rd"] = (flags & 0x0100) >> 8
    # ra (8th bit in flags)
    msgHeader["ra"] = (flags & 0x0080) >> 7
    # (Note: reserved field is 9-11th bits. not needed)
    # rcode (12-15th bits in flags) 
    msgHeader["rcode"] = (flags & 0x000f)

    # number of entries in each section
    qst = header[2]
    msgHeader["qst"] = qst

    ans = header[3]
    msgHeader["ans"] = ans

    auth = header[4]
    msgHeader["auth"] = auth

    add = header[5]
    msgHeader["add"] = add
    #skip question name
    offset = 16 + len(queryName)
    
    #unpack the authority section data
    answers = []
    count = ans if ans > 0 else auth
    for i in range(count):
        # get name
        name = decodeName(response, offset)
        offset += name["length"]

        #get answer fields
        ansFields = struct.unpack_from(">HHIH", response, offset)
        ansType = ansFields[0]
        ansClass = ansFields[1]
        ttl = ansFields[2]
        rdLength = ansFields[3]
        offset += 10
        if ansType == 1:
            # Type A: get ip
            ip = {"name": name['name'], "ansType": ansType, "ansClass": ansClass, "ttl": ttl, "rdLength": rdLength, "data": decodeIP(response, offset, rdLength)}
            answers.append(ip)
        elif ansType == 2 or ansType == 5:
            if ans > 0 and ansType != queryType:
                # if given a CNAME instead of answer being looked for, restart query with the CNAME
                reAnswer = findAnswer(f"{decodeName(response, offset)['name'][:-1]}", queryType, timeout)
                answers = answers + reAnswer["data"]
            else:
                # Type NS and CNAME: get name server
                nameServer = {"name": name['name'], "ansType": ansType, "ansClass": ansClass, "ttl": ttl, "rdLength": rdLength, "data": decodeName(response, offset)["name"]}
                answers.append(nameServer)
        offset += rdLength

    # filter out duplicate answers
    answers = [dict(tAns) for tAns in {tuple(ans.items()) for ans in answers}]
    msg = {"header": msgHeader, "data": answers}
    return msg

def formatDomain(domainName):
    dnsQuery = b''
    for domainPart in domainName.split("."):
        dnsQuery += struct.pack("!B", len(domainPart))
        for character in domainPart:
            dnsQuery += struct.pack("!c", character.encode('utf-8'))
    dnsQuery += struct.pack('!b', 0)
    return dnsQuery

def createQuery(domainName, queryType):
    query_id = random.randint(0, 65535)
    flags = 0
    qst = 1
    ans = 0
    auth = 0
    add = 0

    # DNS header
    dnsHeader = struct.pack("!HHHHHH", query_id, flags, qst, ans, auth, add)
    #DNS question
    dnsQuestion = formatDomain(domainName)
    dnsQuestion += struct.pack('!HH', queryType, 1)
    return dnsHeader + dnsQuestion

# find answer
def findAnswer(domainName, queryType, timeout):
    answer = False
    #create query
    queryData = createQuery(domainName, queryType)
    query = {"queryName": formatDomain(domainName), "data": queryData}
    #read in root hints file
    rootHints = readHints()
    nameServers = list(rootHints.keys())
    while not answer:
        # look for answer
        for index, server in enumerate(nameServers):
            #create socket
            iterSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            iterSock.settimeout(timeout)
            iterSock.connect((server, 53))
            iterSock.sendall(query["data"])
            data = None
            # wait for response from name server
            while data == None:
                try:
                    data = iterSock.recv(1024)
                except socket.timeout:
                    break
            iterSock.close()
            print(index)
            print(index == (len(nameServers) - 1))
            # check if response was recived
            if data != None:
                #decode response
                response = decodeResponse(data, query["queryName"], queryType, timeout)
                #check if answer was found or an error was found (check for server error and no more servers)
                if response["header"]["ans"] > 0 or (response["header"]["rcode"] != 0 and (response["header"]["rcode"] != 2 or (index == len(nameServers) - 1))):
                    answer = True
                elif response["header"]["rcode"] == 2:
                    # if server error an
                    continue
                else:
                    # update list of name servers to check
                    nameServers = [server["data"] for server in response["data"]]
                break
            elif index == (len(nameServers) - 1):
                #check if timeout continuously occurs
                response = {"Header": None, "data": [], "Timeout": True}
                answer = True
    return response

def main():
    #check number of command line args
    if len(sys.argv) < 2 :
        errorFound("Invalid arguments\nUsage: resolver port [timeout=5]")
    host = '127.0.0.1'
    try:
        port = int(sys.argv[1])
    except ValueError:
        errorFound("Invalid arguments\nUsage: resolver port [timeout=5]")
    timeout = 5
    if len(sys.argv) == 3:
        try:
            timeout = float(sys.argv[2])
        except ValueError:
            errorFound("Invalid arguments\nUsage: resolver port [timeout=5]")

    #create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #bind socket to host and port
    sock.bind((host, port))
    print('Socket binding complete')
    #listen for connections
    sock.listen(1)
    while True:
        # create connection
        conn, address = sock.accept()
        query = conn.recv(1024)
        print(f"Recieved request")
        query = pickle.loads(query)
        print("Searching for answers")
        response = findAnswer(query["domain"], query["type"], timeout)
        conn.sendall(pickle.dumps(response))
        print("Response sent")
        conn.close()
    sock.close()

if __name__ == "__main__":
    main()
