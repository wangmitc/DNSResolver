import struct
import random

def errorFound(message):
    print(f"Error: {message}")
    exit()

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


def decodeResponse(response):
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
    # offset = 16 + len(queryName)
    offset = 12
    msgQuestion = {}
    qstName = decodeName(response, offset)
    msgQuestion["name"] = qstName["name"]
    offset += qstName['length']
    qstType = struct.unpack_from(">H", response, offset)[0]
    msgQuestion["qstType"] = qstType
    qstClass = struct.unpack_from(">H", response, offset + 2)[0]
    msgQuestion["qstClass"] = qstClass
    offset += 4
    #unpack the authority section data
    answers = []
    count = ans if ans > 0 else auth
    for i in range(count):
        # get name
        name = decodeName(response, offset)
        print("Name")
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
            print(ip)
            answers.append(ip)
        elif ansType == 2 or ansType == 5 or ansType == 12 or ansType == 15:
            nameServer = {"name": name['name'], "ansType": ansType, "ansClass": ansClass, "ttl": ttl, "rdLength": rdLength, "data": decodeName(response, offset)["name"]}
            answers.append(nameServer)

        offset += rdLength
    
    # filter out duplicate answers
    answers = [dict(tAns) for tAns in {tuple(ans.items()) for ans in answers}]
    msg = {"header": msgHeader, "question": msgQuestion, "data": answers}
    return msg