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
