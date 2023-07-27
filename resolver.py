import socket
import sys
import re
from shared import errorFound, createQuery, decodeResponse

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

# find answer
def findAnswer(query, timeout):
    answer = False
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
            iterSock.sendall(query)
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
                response = decodeResponse(data)
                print(response["header"]["aa"] == 1)
                print(response)
                # if given a CNAME instead of answer being looked for, restart query with the CNAME
                if len(response["data"]) == 1 and response["data"][0]["ansType"] != response["question"]["qstType"] and response["data"][0]["ansType"] == 5:
                    # print(response["data"][0])
                    query = createQuery(response["data"][0]["data"][:-1], response["question"]["qstType"])
                    data = findAnswer(query, timeout)
                    answer = True
                #check if answer was found or an error was found (check for server error and no more servers) or aa flag was set (SOA)
                elif response["header"]["ans"] > 0 or response["header"]["aa"] == 1 or (response["header"]["rcode"] != 0 and (response["header"]["rcode"] != 2 or (index == len(nameServers) - 1))):
                    print("========================= hi hi=========================")
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
                answer = True
    return data

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
        print("Searching for answers")
        response = findAnswer(query, timeout)
        conn.sendall(response)
        print("Response sent")
        conn.close()
    sock.close()

if __name__ == "__main__":
    main()
