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
    nameLength = 0
    isPointer = False
    # get all char for name
    while (char := struct.unpack_from(">B", response, offset)[0]) != 0:
        print(char)
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

        if not isPointer:
            nameLength += 1
    nameChars.append(0)

    if isPointer:
        nameLength += 1
    
    # decode each char
    print(nameChars)
    name = ''
    for char in nameChars:
        if char < 30:
            name += '.'
        else:
            name += chr(int(char))
    print(name)
    return name

def decodeResponse(response, queryName):
    #unpack the header
    header = struct.unpack_from(">HHHHHH", response, 0)
    print(header)
    #MessageID
    x_id = header[0]
    # flags
    flags = header[1]
    print(flags)
    #use masks and bit shifts to extract each flag 
    qr = flags >> 15
    opcode = (flags & 0x7800) >> 11
    aa = (flags & 0x0400) >> 10
    tc = (flags & 0x0200) >> 9
    rd = (flags & 0x0100) >> 8
    ra = (flags & 0x0080) >> 7
    rcode = (flags & 0x000f)

    # number of entries in each section
    qst = header[2]
    ans = header[3]
    auth = header[4]
    add = header[5]
    print(x_id, qr, opcode, aa, tc, rd, ra, rcode, qst, ans, auth, add)

    #unpack question (don't need it)
    #qname
    # qName = b''
    # for i in range(len(queryName)):
    #     qName += struct.unpack_from(">B", response, 12 + i)[0]

    # qtype = struct.unpack_from(">H", response, 12 + len(queryName))[0]
    # qclass = struct.unpack_from(">H", response, 14 + len(queryName))[0]
    # print(qtype, qclass)

    #skip question section
    offset = 16 + len(queryName)

    # unpack answer section
    # get the name

    # nameLength = 0
    
    # name = decodeName(response, offset)
    # the name section
    while struct.unpack_from(">B", response, offset)[0] != 0:
        offset += 1
    ansFields = struct.unpack_from(">HHIH", response, offset)
    ansType = ansFields[0]
    ansClass = ansFields[1]
    ttl = ansFields[2]
    rdLength = ansFields[3]
    print(name, ansType, ansClass, ttl, rdLength)
    # if there are answers
    if ans > 0:
        if ansType == 1:
            #A Type
            decodeName(response, offset)
    else:
        if ansType == 2:
            #NS
            decodeName(response, offset)

    # print(name)
    # answer
    # if ans > 0:
    # #unpack answer
    # #    NameErrortype
    # #     class
    # #     TTL
    # #     rLength
    # #     rData 
    #     print("hi")

    # else:
    #     # get all the name servers from the authority section
        
    #     nameServers = []
    #     for i in range(auth):

            

    #         nameServers.append()
    
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
        # create connection
        conn, address = sock.accept()
        query = conn.recv(1024)
        query = pickle.loads(query)
        print(query)
        # data = conn.recv(1024)
        # print("recieved request")
        # query = pickle.loads(data)
        # print(query)

        # look for answer
        answer = list(rootHints.keys())[0]
        #create socket
        iterSock = socket(AF_INET, SOCK_DGRAM)
        iterSock.settimeout(20)
        iterSock.connect((answer, 53))
        iterSock.sendall(query["data"])
        data = None
        # wait for response from name server
        while data == None:
            try:
                data = iterSock.recv(1024)
                print("got data:")
                print(data)
                decodeResponse(data, query["queryName"])
                # response = data.decode()
            except timeout:
                break
        iterSock.close()
        # nameSect = query['name'].split('.')
        # nameSect.reverse()

        # numQueries = 1
        # answer = list(rootHints.keys())[0]
        # currName = ""
        # nsOutput = ""
        # ansResp = {}
        # ansResp["aa"] = True
        # # check if authoritative answer is not found
        # while ((currName != query['name']) and (re.search(r';; flags:[^;]* aa [^;]*;', (nsOutput := os.popen(f"dig @{answer} {query['name']} NS").read())) == None)):
        #     #check if non authoritive answer is given (cached data)
        #     if re.search(f';; ANSWER SECTION:', nsOutput):
        #         ansResp["aa"] = False
        #         break
        #     print(nsOutput)
        #     # find next name server
        #     currName = nameSect[:numQueries]
        #     currName.reverse()
        #     currName = ".".join(currName) + "."
        #     for line in nsOutput.splitlines():
        #         if re.match(rf"^{currName}", line):
        #             break
        #     answer = re.split('\t+', line)[4].strip()
        #     numQueries += 1

        # # get IP
        # nsOutput = os.popen(f"dig @{answer} {query['name']} A").read()
        # print(nsOutput)
        # print()
        # for line in nsOutput.splitlines():
        #     if flags := re.findall(r';; flags:[^;]*;', line):
        #         ansResp['tr'] = re.findall(r';; flags:[^;]* tr [^;]*;', flags[0]) != []
        #     elif re.match(rf"^;{currName}", line):
        #         # question = line
        #         ansResp["question"] = line
        #     elif re.match(rf"^{currName}", line):
        #         # answer = re.split('\t+', line)[4].strip()
        #         print(nsOutput, end="")
        #         ansResp["answer"] = line
        #         response = pickle.dumps(ansResp)
        #         conn.sendall(response)
        #         break

        conn.close()
        # break
    sock.close()

if __name__ == "__main__":
    main()
