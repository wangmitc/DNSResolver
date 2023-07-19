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
    try:
        while True:
            #create connection
            conn, address = sock.accept()
            print(conn)
            data = conn.recv(1024)
            print("recieved request")
            query = pickle.loads(data)

            conn.close()
    except KeyboardInterrupt:
        print("interuppted")





if __name__ == "__main__":
    main()
