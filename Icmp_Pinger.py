import os
import sys
import struct
import time
import select
import socket


ICMP_ECHO_REQUEST = 8
TIMEOUT = 1.0  # seconds


def checksum(source_bytes):
    #Compute the Internet Checksum of the supplied bytes.
    countTo = (len(source_bytes) // 2) * 2
    csum = 0
    count = 0


    while count < countTo:
        thisVal = source_bytes[count + 1] * 256 + source_bytes[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count += 2


    if countTo < len(source_bytes):
        csum = csum + source_bytes[-1]
        csum = csum & 0xffffffff


    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def receiveOnePing(mySocket, ID, timeout, destAddr):
    timeLeft = timeout
    while True:
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = time.time() - startedSelect


        if whatReady[0] == []:
            return "Request timed out."


        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024)


        #start

         ### Fetch the ICMP header from the IP packet
        receive_header = recPacket[20:28]  # ICMP header is after 20-byte IP header
        rtype, code, recchecksum, packetid, sequence = struct.unpack("bbHHh", receive_header)


        if rtype == 0 and packetid == ID: 
            bytesInDouble = struct.calcsize("d")
            timeSent = struct.unpack("d", recPacket[28:28 + bytesInDouble])[0]
            return timeReceived - timeSent
                  
                  ## Fill in end


        timeLeft -= howLongInSelect
        if timeLeft <= 0:
            return "Request timed out."


def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    myChecksum = 0
    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())


    # Calculate the checksum on the data and the dummy header.
    packet = header + data


    myChecksum = checksum(packet)


    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network byte order
        myChecksum = socket.htons(myChecksum) & 0xffff
    else:
        myChecksum = socket.htons(myChecksum)


    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data
    mySocket.sendto(packet, (destAddr, 1))
    # Both LISTS and TUPLES consist of a number of objects
    # which can be referenced by their position number within the object.


def doOnePing(destAddr, timeout):
    try:
        mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        sys.exit("You must run this program as administrator/root.")


    myID = os.getpid() & 0xFFFF
    sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)
    mySocket.close()
    return delay


def ping(host, timeout=1):
    # timeout=1 means: If one second goes by without a reply from the server,
    # the client assumes that either the client's ping or the server's pong is lost
    dest = socket.gethostbyname(host)
    print("Pinging " + dest + " using ICMP")
    print("")
    # Send ping requests to a server separated by approximately one second
    while True:
        delay = doOnePing(dest, timeout)
        print(delay)
        time.sleep(1)


ping("127.0.0.1.")