from socket import *
import pickle
import sys
import re
import struct

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
    print(ip)
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

def decodeResponse(response, queryName):
    #unpack the header
    header = struct.unpack_from(">HHHHHH", response, 0)
    print(header)
    msgHeader = {}
    #MessageID
    msgHeader["id"] = header[0]
    # flags
    flags = header[1]
    print(flags)
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

    #skip question section
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
            print("found answer")
            ip = {"name": name['name'], "ansType": ansType, "ansClass": ansClass, "ttl": ttl, "rdLength": rdLength, "data": decodeIP(response, offset, rdLength)}
            answers.append(ip)

        if ansType == 2:
            # Type NS: get name server
            nameServer = {"name": name['name'], "ansType": ansType, "ansClass": ansClass, "ttl": ttl, "rdLength": rdLength, "data": decodeName(response, offset)["name"]}
            print(nameServer)
            answers.append(nameServer)
            offset += rdLength

    print(answers)
    msg = {"header": msgHeader, "data": answers}
    return msg
    

def main():
    #check number of command line args
    if len(sys.argv) < 2 :
        errorFound("Invalid arguments\nUsage: resolver port")
    host = '127.0.0.1'
    port = int(sys.argv[1])
    print(host, port)

    #read in root hints file
    rootHints = readHints()
    print(rootHints)

    #create socket
    sock = socket(AF_INET, SOCK_STREAM)
    #bind socket to host and port
    sock.bind((host, port))
    print('socket binding complete')
    #listen for connections
    sock.listen(1)
    while True:
        answer = False
        nameServers = list(rootHints.keys())
        # create connection
        conn, address = sock.accept()
        query = conn.recv(1024)
        query = pickle.loads(query)
        print(query)
        while not answer:
            # look for answer
            # answer = list(rootHints.keys())[0]
            for server in nameServers:
                #create socket
                iterSock = socket(AF_INET, SOCK_DGRAM)
                iterSock.settimeout(20)
                print(server)
                iterSock.connect((server, 53))
                iterSock.sendall(query["data"])
                data = None
                # wait for response from name server
                while data == None:
                    try:
                        data = iterSock.recv(1024)
                        print("got data:")
                        print(data)
                    except timeout:
                        break
                iterSock.close()

                # check if response was recived
                if data != None:
                    #decode response
                    response = decodeResponse(data, query["queryName"])
                    #check if answer was found or an error was found
                    if response["header"]["ans"] > 0 or response["header"]["rcode"] != 0:
                        answer = True
                    else:
                        # update list of name servers to check
                        nameServers = [ server["data"] for server in response["data"]]
                        print("hola")
                        print(nameServers)
                    break
        conn.sendall(pickle.dumps(response))
        conn.close()
    sock.close()

if __name__ == "__main__":
    main()
