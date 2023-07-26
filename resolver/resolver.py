from socket import *
import pickle
import sys
import re
import os
import struct
# from dnslib import DNSRecord

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

def decodeName(response, offset):
    nameChars = []
    char = None
    isPointer = False

    # get all char for name
    while (char := struct.unpack_from(">B", response, offset)[0]) != 0:
        # check if name field is pointer (first two bytes are 1)
        if char >= 192:
            # go to pointer address
            # (char << 8) >= 0b1100000000000000
            # offset = char << 8 + (next pointer bit) - 0b1100000000000000 - 1
            offset = ((char << 8) + struct.unpack_from(">B", response, offset + 1)[0] - 0xc000) - 1
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
    #use masks and bit shifts to extract each flag 
    # qr
    msgHeader["id"] = flags >> 15
    # opcode
    msgHeader["opcode"] = (flags & 0x7800) >> 11
    # aa
    msgHeader["aa"] = (flags & 0x0400) >> 10
    # tc
    msgHeader["tc"] = (flags & 0x0200) >> 9
    # rd
    msgHeader["rd"] = (flags & 0x0100) >> 8
    # ra
    msgHeader["ra"] = (flags & 0x0080) >> 7
    # rcode
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
    # print(x_id, qr, opcode, aa, tc, rd, ra, rcode, qst, ans, auth, add)

    #skip question section
    offset = 16 + len(queryName)
    
    # offset += 10
    # if there are answers
    if ans > 0:
        # unpack answer data
        print("found answer")
        # name = decodeName(response, offset)
        # offset += name["length"]
        # ansFields = struct.unpack_from(">HHIH", response, offset)
        # ansType = ansFields[0]
        # ansClass = ansFields[1]
        # ttl = ansFields[2]
        # rdLength = ansFields[3]
        # offset += name["length"] + 10
        # if ansType == 1:
        #     #A Type
        #     decodeName(response, offset)
        return {}
    else:
        #unpack the authority section data
        nameServers = []
        print(auth)
        for i in range(auth):
            # get name
            name = decodeName(response, offset)
            offset += name["length"]

            #get answer fields
            ansFields = struct.unpack_from(">HHIH", response, offset)
            ansType = ansFields[0]
            ansClass = ansFields[1]
            ttl = ansFields[2]
            rdLength = ansFields[3]

            # get name server
            offset += 10
            nameServer = {"name": name, "ansType": ansType, "ansClass": ansClass, "ttl": ttl, "rdLength": rdLength, "data": decodeName(response, offset)["name"]}
            print(nameServer)
            nameServers.append(nameServer)
            offset += rdLength
        print(nameServers)
        msg = {"header": msgHeader, "auth": nameServers}
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
    answer = False
    nameServers = list(rootHints.keys())
    #listen for connections
    sock.listen(1)
    # create connection
    conn, address = sock.accept()
    query = conn.recv(1024)
    query = pickle.loads(query)
    print(query)
    while not answer:
        # create connection
        # conn, address = sock.accept()
        # query = conn.recv(1024)
        # query = pickle.loads(query)
        # print(query)

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
                #check if answer was found
                if response["header"]["ans"] > 0:
                    answer = True
                else:
                    # update list of name servers to check
                    nameServers = [ server["data"] for server in response["auth"]]
                    print("hola")
                    print(nameServers)
                break


        conn.close()
        # break
    sock.close()

if __name__ == "__main__":
    main()
