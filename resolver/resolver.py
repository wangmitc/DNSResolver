from socket import *
import pickle
import sys
import re
import os

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
        #create connection
        conn, address = sock.accept()
        data = conn.recv(1024)
        print("recieved request")
        query = pickle.loads(data)
        print(query)
        
        #look for answer
        nameSect = query['name'].split('.')
        nameSect.reverse()

        numQueries = 1
        answer = list(rootHints.keys())[0]
        currName = ""
        nsOutput = ""
        ansResp = {}
        ansResp["aa"] = True
        # check if authoritative answer is not found
        while ((currName != query['name']) and (re.search(r';; flags:[^;]* aa [^;]*;', (nsOutput := os.popen(f"dig @{answer} {query['name']} NS").read())) == None)):
            #check if non authoritive answer is given (cached data)
            if re.search(f';; ANSWER SECTION:', nsOutput):
                ansResp["aa"] = False
                break
            print(nsOutput)
            # find next name server
            currName = nameSect[:numQueries]
            currName.reverse()
            currName = ".".join(currName) + "."
            for line in nsOutput.splitlines():
                if re.match(rf"^{currName}", line):
                    break
            answer = re.split('\t+', line)[4].strip()
            numQueries += 1

        # get IP
        nsOutput = os.popen(f"dig @{answer} {query['name']} A").read()
        print(nsOutput)
        print()
        for line in nsOutput.splitlines():
            if flags := re.findall(r';; flags:[^;]*;', line):
                ansResp['tr'] = re.findall(r';; flags:[^;]* tr [^;]*;', flags[0]) != []
            elif re.match(rf"^;{currName}", line):
                # question = line
                ansResp["question"] = line
            elif re.match(rf"^{currName}", line):
                # answer = re.split('\t+', line)[4].strip()
                print(nsOutput, end="")
                ansResp["answer"] = line
                response = pickle.dumps(ansResp)
                conn.sendall(response)
                break

        conn.close()
    #     break
    # sock.close()

if __name__ == "__main__":
    main()
