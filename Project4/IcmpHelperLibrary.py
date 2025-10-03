# ################################################################################################################ #
# Author: Seth Baker                                                                                               #
# Programming Project TraceRoute (#4)                                                                              #
#                                                                                                                  #
# ################################################################################################################ #

# #################################################################################################################### #
# Imports                                                                                                              #
# #################################################################################################################### #
import os
from socket import *
import struct
import time
import select

# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
# #################################################################################################################### #
class IcmpHelperLibrary:
    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           #
    # ################################################################################################################ #
    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #
        # ############################################################################################################ #
        __icmpTarget = ""  # Remote Host
        __destinationIpAddress = ""  # Remote Host IP Address
        __header = b''  # Header after byte packing
        __data = b''  # Data after encoding
        __dataRaw = ""  # Raw string data before encoding
        __icmpType = 0  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0  # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0  # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0  # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 30
        __ttl = 255  # Time to live

        __DEBUG_IcmpPacket = False  # Allows for debug output

        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        # ############################################################################################################ #
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        def getDestinationIpAddress(self):
            return self.__destinationIpAddress

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        # ############################################################################################################ #
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                try:
                    self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())
                except gaierror:
                    print(f"Cannot resolve hostname: {self.__icmpTarget}")
                    self.__destinationIpAddress = None

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff  # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2
            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff  # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)  # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum  # Rotate and add

            answer = ~checksum  # Invert bits
            answer = answer & 0xffff  # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                         self.getIcmpType(),  # 8 bits / 1 byte  / Format code B
                                         self.getIcmpCode(),  # 8 bits / 1 byte  / Format code B
                                         self.getPacketChecksum(),  # 16 bits / 2 bytes / Format code H
                                         self.getPacketIdentifier(),  # 16 bits / 2 bytes / Format code H
                                         self.getPacketSequenceNumber()  # 16 bits / 2 bytes / Format code H
                                         )

        def __encodeData(self):
            data_time = struct.pack("d", time.time())  # Used to track overall round trip time
            # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()  # packHeader() and encodeData() transfer data to their respective bit
            # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()  # Result will set new checksum value
            self.__packHeader()  # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # Hint: Work through comparing each value and identify if this is a valid response.

            '''Update the __validateIcmpReplyPacketWithOriginalPingData() function:
            Confirm the following items received are the same as what was sent:
                sequence number
                packet identifier
                raw data'''

            icmpReplyPacket.setIsValidResponse(True)

            # Initialize isValid var to True
            isValid = True

            # If sequence number is not the same, then it's invalid
            if icmpReplyPacket.getIcmpSequenceNumber() != self.getPacketSequenceNumber():
                icmpReplyPacket.setIsValidSequenceNumber(False)
                isValid = False

            # If IcmpId number is not the same, then it's invalid
            if icmpReplyPacket.getIcmpIdentifier() != self.getPacketIdentifier():
                icmpReplyPacket.setIsValidIdentifier(False)
                isValid = False

            # If data is not the same, then it's invalid
            if icmpReplyPacket.getIcmpData() != self.getDataRaw():
                icmpReplyPacket.setIsValidData(False)
                isValid = False

            icmpReplyPacket.setIsValidResponse(isValid)

        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self):
            if len(self.__icmpTarget.strip()) <= 0 or self.__destinationIpAddress is None:
                self.setIcmpTarget("127.0.0.1")

            print("Pinging (" + self.__icmpTarget + ") " + self.__destinationIpAddress)

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print("  *        *        *        *        *    Request timed out.")
                    return None # Indicate timeout

                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                IcmpHelperLibrary.round_trip_times.append(timeReceived - pingStartTime)  # appends the round trip times by using the time recieved and the ping start time
                IcmpHelperLibrary.packet_loss_sent += 1  # this will increment the sent packets
                if timeLeft <= 0:
                    print("  *        *        *        *        *    Request timed out (By no remaining time left).")
                    return None # Indicate timeout

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = struct.unpack("bb", recvPacket[20:22])
                    IcmpHelperLibrary.packet_loss_received += 1  # increment the recieved packets
                    if icmpType == 11:  # Time Exceeded
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                              (
                                  self.getTtl(),
                                  (timeReceived - pingStartTime) * 1000,
                                  icmpType,
                                  icmpCode,
                                  addr[0]
                              )
                              )
                        return addr[0]

                    elif icmpType == 3:  # Destination Unreachable
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                              (
                                  self.getTtl(),
                                  (timeReceived - pingStartTime) * 1000,
                                  icmpType,
                                  icmpCode,
                                  addr[0]
                              )
                              )
                        return addr[0]

                    elif icmpType == 0:  # Echo Reply
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr)
                        return addr[0] # Echo reply is the end and therefore should return

                    else:
                        print("error")
                        return None

            except timeout:
                print("  *        *        *        *        *    Request timed out (By Exception).")
                return None

            except OSError as e:
                print(f"OSError: {e}")
                return None

            finally:
                mySocket.close()

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i + 1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False
        '''Set the valid data variable in the IcmpPacket_EchoReply class based the outcome of the data comparison.'''
        IcmpIdentifier_isValid = True
        IcmpSequenceNumber_isValid = True
        IcmpData_isValid = True

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        # ############################################################################################################ #
        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        # ############################################################################################################ #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)  # Used to track overall round trip time
            # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def isValidResponse(self):
            return self.__isValidResponse

        def getIsValidSequenceNumber(self):
            return self.IcmpSequenceNumber_isValid

        def getIsValidIdentifier(self):
            return self.IcmpIdentifier_isValid

        def getIsValidData(self):
            return self.IcmpData_isValid

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        # ############################################################################################################ #
        ''' Create variables within the IcmpPacket_EchoReply class that identify whether each value that 
            can be obtained from the class is valid. For example, the IcmpPacket_EchoReply class 
            has an IcmpIdentifier. Create a variable, such as IcmpIdentifier_isValid, along with a getter
            function, such as getIcmpIdentifier_isValid(), and setting function, such as setIcmpIdentifier_isValid(), 
            so you can easily track and identify which data points within the echo reply are valid.'''

        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        def setIsValidIdentifier(self, booleanValue):
            self.IcmpIdentifier_isValid = booleanValue

        def setIsValidSequenceNumber(self, booleanValue):
            self.IcmpSequenceNumber_isValid = booleanValue

        def setIsValidData(self, booleanValue):
            self.IcmpData_isValid = booleanValue

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        # ############################################################################################################ #
        def printResultToConsole(self, ttl, timeReceived, addr):
            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]
            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d        Identifier=%d    Sequence Number=%d    %s" %
                  (
                      ttl,
                      (timeReceived - timeSent) * 1000,
                      self.getIcmpType(),
                      self.getIcmpCode(),
                      self.getIcmpIdentifier(),
                      self.getIcmpSequenceNumber(),
                      addr[0]
                  )
                  )

            if not self.isValidResponse():
                if not self.getIsValidIdentifier():
                    print("Expected ID:", self.getPacketIdentifier(), "  Actual ID:", self.getIcmpIdentifier())

                if not self.getIsValidSequenceNumber():
                    print("Expected Sequence Number:", self.getPacketSequenceNumber(), "  Actual Sequence Number:",
                          self.getIcmpSequenceNumber())

                if not self.getIsValidData():
                    print("Expected Data:", self.getRawData(), "  Actual Data:", self.getIcmpData())

    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False  # Allows for debug output

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    # ################################################################################################################ #

    round_trip_times = []  # "total time taken to send the first packet to the destination, plus the time taken to receive the response packet"
    packet_loss_sent = 0  # set the incoming message
    packet_loss_received = 0  # set for the outcoming for the calculation

    icmpErrorCodes = {
        3: {0: "Net Unreachable",
            1: "Host Unreachable",
            2: "Protocol Unreachable",
            3: "Port Unreachable",
            4: "Fragmentation Needed and Don't Fragment was Set",
            5: "Source Route Failed",
            6: "Destination Network Unknown",
            7: "Destination Host Unknown",
            8: "Source Host Isolated",
            9: "Communication with Destination Network is Administratively Prohibited",
            10: "Communication with Destination Host is Administratively Prohibited"},

        11: {0: "Time to Live exceeded in Transit",
             1: "Fragment Reassembly Time Exceeded"}
    }

    def __sendIcmpEchoRequest(self, host):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        for i in range(4):
            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)  # Get as 16 bit number - Limit based on ICMP header standards
            # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)
            icmpPacket.sendEchoRequest()  # Build IP

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            # we should be confirming values are correct, such as identifier and sequence number and data

        divide_round_trip_times = sum(self.round_trip_times) / len(self.round_trip_times)
        average_round_trip_times = (divide_round_trip_times * 1000)
        print(self.round_trip_times)
        print("\nRound Trip Times:")
        print("Minimum:", min(self.round_trip_times) * 1000, "ms;", "Maximum:", max(self.round_trip_times) * 1000,
              "ms;", "Average: ", average_round_trip_times, "ms")

        # The calculation method is: [(sent message - recived message)/ sent message]*100%.
        packet_loss_rate = (1 - self.packet_loss_received / self.packet_loss_sent) * 100
        print("\nThe Packet Loss Rate is:", packet_loss_rate, "\n")

    def __sendIcmpTraceRoute(self, host):
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        ttl = 1
        while ttl <= 30:
            icmpPacket = IcmpHelperLibrary.IcmpPacket()
            randomIdentifier = (os.getpid() & 0xffff)

            packetIdentifier = randomIdentifier
            packetSequenceNumber = 1  # Keep this fixed for traceroute

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)
            icmpPacket.setIcmpTarget(host)
            icmpPacket.setTtl(ttl)
            ip_address = icmpPacket.sendEchoRequest()

            if ip_address is None:
                break # Break if there is a timeout
            if icmpPacket.getDestinationIpAddress() == ip_address:
                break # Exit when the destination is reached
            ttl += 1

    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    # ################################################################################################################ #
    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)


# #################################################################################################################### #
# main()                                                                                                               #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()

    # Choose one of the following by uncommenting out the line
    icmpHelperPing.sendPing("209.233.126.254")
    # icmpHelperPing.sendPing("www.google.com")
    # icmpHelperPing.sendPing("gaia.cs.umass.edu")
    # icmpHelperPing.traceRoute("164.151.129.20")
    # icmpHelperPing.traceRoute("122.56.99.243")


if __name__ == "__main__":
    main()
