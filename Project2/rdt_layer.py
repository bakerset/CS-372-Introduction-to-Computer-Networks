from segment import Segment


# #################################################################################################################### #
# RDTLayer                                                                                                             #
#                                                                                                                      #
# Description:                                                                                                         #
# The reliable data transfer (RDT) layer is used as a communication layer to resolve issues over an unreliable         #
# channel.                                                                                                             #
#                                                                                                                      #
#                                                                                                                      #
# Notes:                                                                                                               #
# This file is meant to be changed.                                                                                    #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #


class RDTLayer(object):
    # ################################################################################################################ #
    # Class Scope Variables                                                                                            #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    DATA_LENGTH = 4  # in characters                     # The length of the string data that will be sent per packet...
    FLOW_CONTROL_WIN_SIZE = 15  # in characters          # Receive window size for flow-control
    sendChannel = None
    receiveChannel = None
    dataToSend = ''
    currentIteration = 0  # Use this for segment 'timeouts'

    # Add items as needed
    sentData = ''
    rcvdData = ''
    currWindow = [0, 4]
    currSeqNum = 0
    expectedAck = 4
    serverData = []
    flow_control_segs = 3

    # ################################################################################################################ #
    # __init__()                                                                                                       #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __init__(self):
        self.sendChannel = None
        self.receiveChannel = None
        self.dataToSend = ''
        self.currentIteration = 0

        # Add items as needed
        self.countSegmentTimeouts = 0
        self.seqnum = 0
        self.receiveData = ''
        self.receiveArr = []
        self.missingData = []
        self.preMissing = 0  # 0 == false; 1 == true
        self.currAck = 0
        self.role = 0  # 0 == server; 1 == client

    # ################################################################################################################ #
    # setSendChannel()                                                                                                 #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Called by main to set the unreliable sending lower-layer channel                                                 #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def setSendChannel(self, channel):
        self.sendChannel = channel

    # ################################################################################################################ #
    # setReceiveChannel()                                                                                              #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Called by main to set the unreliable receiving lower-layer channel                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def setReceiveChannel(self, channel):
        self.receiveChannel = channel

    # ################################################################################################################ #
    # setDataToSend()                                                                                                  #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Called by main to set the string data to send                                                                    #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def setDataToSend(self, data):
        self.dataToSend = data
        
        # https://pythonexamples.org/python-split-string-into-specific-length-chunks/
        splitData = [data[x:x + (RDTLayer.DATA_LENGTH)] for x in range(0, len(data), RDTLayer.DATA_LENGTH)]

    # ################################################################################################################ #
    # getDataReceived()                                                                                                #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Called by main to get the currently received and buffered string data, in order                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def getDataReceived(self):
        return self.receiveData

    # ################################################################################################################ #
    # processData()                                                                                                    #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # "timeslice". Called by main once per iteration                                                                   #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def processData(self):
        self.currentIteration += 1
        self.processSend()
        self.processReceiveAndSendRespond()

    # ################################################################################################################ #
    # processSend()                                                                                                    #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Manages Segment sending tasks                                                                                    #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def processSend(self):
        splitData = [self.dataToSend[i:i + self.DATA_LENGTH] for i in range(0, len(self.dataToSend), self.DATA_LENGTH)]

        if splitData != None:
            self.role = 1

        if self.currentIteration == 1 and self.role == 1:
            n = 0
            # Sending data within the flow control window size
            while n < self.flow_control_segs and n < len(splitData) - self.seqnum:
                tempData = Segment()
                tempData.setData(str(n + self.seqnum), splitData[n + self.seqnum])
                print("Sending segment: ", tempData.to_string())

                self.sendChannel.send(tempData)
                n += 1

            self.seqnum = n + self.seqnum

    # ################################################################################################################ #
    # processReceive()                                                                                                 #
    #                                                                                                                  #
    # Description:                                                                                                     #
    # Manages Segment receive tasks                                                                                    #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def processReceiveAndSendRespond(self):
        segmentAck = Segment()  # Segment acknowledging packet(s) received

        listIncomingSegments = self.receiveChannel.receive()

        sortedList = []
        receiveAck = []

        splitData = [self.dataToSend[i:i + self.DATA_LENGTH] for i in range(0, len(self.dataToSend), self.DATA_LENGTH)]

        for i in range(len(listIncomingSegments)):
            listIncomingSegments[i].printToConsole()
            sortedList.append(int(listIncomingSegments[i].seqnum))

        sortedList.sort(reverse=True)

        if len(splitData) == 0 and self.preMissing == 0:
            for i in range(self.flow_control_segs):
                self.receiveArr.append(None)

        for i in range(len(sortedList)):
            if sortedList[i] != -1:
                for j in range(len(listIncomingSegments)):
                    if listIncomingSegments[j].checkChecksum() == True and int(
                            listIncomingSegments[j].seqnum) == sortedList[i] and self.receiveArr[sortedList[i]] == None:
                        self.receiveArr[sortedList[i]] = listIncomingSegments[j].payload

            else:
                receiveAck.append(int(listIncomingSegments[i].acknum))

        # Collect missing data
        for i in range(len(self.receiveArr)):
            if self.receiveArr[i] == None:
                self.missingData.append(i)

            elif self.missingData.count(i) > 0:
                self.missingData.remove(i)

        self.missingData = list(set(self.missingData))

        if len(splitData) > 0:
            if len(receiveAck) > 0:
                dataMatchServer = 0
                for i in range(len(receiveAck)):
                    if receiveAck[i] == self.seqnum:
                        dataMatchServer = 1

                if dataMatchServer != 1:
                    receiveAck.sort()
                    for i in range(0, len(receiveAck)):
                        if len(splitData) > receiveAck[i]:
                            tempData = Segment()
                            tempData.setData(str(receiveAck[i]), splitData[receiveAck[i]])
                            print("Sending segment: ", tempData.to_string())
                            self.sendChannel.send(tempData)

                            # As per instructors suggestion, keeping track of segment timeouts
                            self.countSegmentTimeouts += 1

                elif self.currentIteration > 1:
                    n = 0
                    while n < (len(splitData) - self.seqnum) and n < self.flow_control_segs:
                        tempData = Segment()
                        tempData.setData(str(n + self.seqnum), splitData[n + self.seqnum])
                        print("Sending segment: ", tempData.to_string())
                        self.sendChannel.send(tempData)
                        n += 1
                    self.seqnum = n + self.seqnum

        else:
            self.missingData.sort()
            if len(self.missingData) == 0:
                self.receiveData = ''
                for i in range(len(self.receiveArr)):
                    self.currAck = max(self.currAck, i)
                    self.receiveData = self.receiveData + self.receiveArr[i]
                self.currAck += 1
                segmentAck.setAck(self.currAck)
                self.sendChannel.send(segmentAck)
                print("Sending ack: ", segmentAck.to_string())
                self.preMissing = 0
            else:
                self.receiveData = ''
                for x in range(self.missingData[0]):
                    self.currAck = max(self.currAck, x)
                    self.receiveData = self.receiveData + self.receiveArr[x]
                for x in range(len(self.missingData)):
                    temp = Segment()
                    temp.setAck(self.missingData[x])
                    self.sendChannel.send(temp)
                    print("Sending ack: ", temp.to_string())

                self.preMissing = 1


    # Sources
    # Python examples for splitting strings into specific length chunks: 
    # https://pythonexamples.org/python-split-string-into-specific-length-chunks/