from usbutility import debyteifyLittleEndian, debyteify, byteify, valueOrDefault
import sys

#For specifying URB format
Linux=0
USBPcap=1
Vizsla=2

class CaptureError(Exception):
    def __init__(self, message):
        super(CaptureError, self).__init__(message)
 
class CaptureOrderError(CaptureError):
    def __init__(self, message, transaction, capturePoint):
        super(CaptureOrderError, self).__init__(message)
        self.transaction=transaction
        self.capturePoint=capturePoint

class CaptureFormatError(CaptureError):
     pass

class CapturePoint(object):
    #Used for .controlTransferStage for USBPcap
    SetupStage=0x0
    DataStage=0x1
    StatusStage=0x2

    #buffer is complete buffer grabbed from capture.
    def __init__(self, buffer, format=USBPcap, capCounter=None, capBase=0): 
        self.format=format
        self.rawData=buffer
        self.capCounter=capCounter
        if format==USBPcap:
            self.initialFlag = True #Set when suitable
                                    #format for first capture buf of a complete USBTransaction.
                                    #Most buffers types are solo in this format,
                                    #so defaults to True
            self.endFlag = True #Set when suitable 
                                #format for last buffer capture buf of a complete USBTransaction
                                #Most buffers types are solo in this format,
                                #so defaults to True
            self.controlDataFlag = False
 
            urbLength=debyteifyLittleEndian(buffer[0:2])
            if (urbLength < 27) or (urbLength > len(buffer)):
                raise CaptureFormatError("Data is in wrong format")

            auxLength=0
            self.irpID=debyteifyLittleEndian(buffer[2:10])
            self.usbdStatus=debyteifyLittleEndian(buffer[10:14]) 
            self.busID=buffer[18]
            self.deviceID=debyteifyLittleEndian(buffer[19:21])
            self.endPoint=buffer[21]
            self.direction=(buffer[21]>>7) != 0
            
            self.type=buffer[22] 
            packetDataLength=debyteifyLittleEndian(buffer[23:27])
            
            if (packetDataLength + urbLength) != len(buffer):
                if (packetDataLength + urbLength <= 65535): #Capture gets truncated apparently
                    raise CaptureFormatError("Data is in wrong format")
        
            if self.type == USBTransaction.CONTROL:
                self.initialFlag = False #Control transactions generate 3 capture events, gotta figure out which
                self.endFlag = False #Control transactions generate 3 capture, gotta figure out which
                self.controlTransferStage=buffer[27] #This is unique to USBPcap
                if self.controlTransferStage==CapturePoint.SetupStage:
                    self.initialFlag = True #Only SetupStage is an initial even for a control transaction
                    auxLength=8 #Size of setup stuff.
                    controlData=buffer[urbLength:urbLength+8]
                    self.setupControl(controlData)
                    self.controlDataFlag=True
                if self.controlTransferStage==CapturePoint.StatusStage:
                    self.endFlag=True

                self.mainWriteFlag = (self.direction == USBTransaction.Outbound) and \
                    (self.controlTransferStage==CapturePoint.DataStage)
                self.mainReadFlag = (self.direction == USBTransaction.Inbound) and \
                    (self.controlTransferStage==CapturePoint.DataStage)
            else:
                #Single state command, if we read or write, we do it here.
                self.mainReadFlag = self.direction == USBTransaction.Inbound
                self.mainWriteFlag = self.direction == USBTransaction.Outbound

            trueUrbLength=urbLength+auxLength
            self.payloadLength=packetDataLength-auxLength

            self.urb=buffer[:trueUrbLength]
            self.payload=buffer[trueUrbLength:trueUrbLength+self.payloadLength]

        elif format==Linux:
            urbLength=64
            if urbLength > len(buffer):
                raise CaptureFormatError("Data is in wrong format")

            urb=buffer[:urbLength]
            self.urb=urb
            self.irpID=debyteifyLittleEndian(urb[0:8])
            urbType=chr(urb[8]) #This is unique to Linux format.
                                #'S' for SUBMIT, 'C' for COMPLETE
            if (urbType != 'S') and (urbType != 'C'):
                raise CaptureFormatError("Data is in wrong format")
            self.urbType=urbType 

            self.initialFlag= self.urbType=='S';
            self.endFlag= self.urbType=='C';
                                  
            self.type=urb[9]
            self.endPoint=urb[10]
            self.direction=(urb[10]>>7) != 0
            self.deviceID=urb[11]
            self.busID=debyteifyLittleEndian(urb[12:14])
            self.usbdStatus=debyteifyLittleEndian(urb[28:32]) 
            extraPacketLength=debyteifyLittleEndian(urb[36:40])

            self.controlDataFlag=False
            if self.type == USBTransaction.CONTROL:
                if self.urbType == 'S':
                    controlData=urb[40:48]
                    self.setupControl(controlData)
                    self.controlDataFlag=True

            self.mainWriteFlag = (self.direction == USBTransaction.Outbound) and \
                 (self.urbType == 'S')
            self.mainReadFlag = (self.direction == USBTransaction.Inbound) and \
                 (self.urbType == 'C')

            self.payloadLength=debyteifyLittleEndian(urb[36:40])
            self.payload=buffer[urbLength:urbLength+self.payloadLength]
            if (urbLength + self.payloadLength) != len(buffer):
                raise CaptureFormatError("Data is in wrong format")

        elif format==Vizsla:
            urbLength=8 #Simulated urb created by DumpVizslaIterator
            #URB definition
            #entry 0 is deviceID
            #entry 1 is endPoint ....bit 7 is set to direction.
            #entry 2 is type..IE USBTransaaction.CONTROL, etc.
            #entry 3 is 0 if SETUP, 1 if anything else. 
            #entry 4-7 is 32 bit line number.
            self.capCounter=debyteify( buffer[4:8] )+capBase
           
            if urbLength > len(buffer):
                raise CaptureFormatError("Data is in wrong format")
            urb=buffer[:urbLength]
            self.urb=urb
 
            self.busID=None #Unknown in Vizsla captures.
            self.deviceID=urb[0]
            self.endPoint=urb[1]
            self.type = urb[2]
            self.direction = (self.endPoint >> 7) != 0
            self.urbStage=urb[3] #0 if SETUP, 1 if IN or OUT, 2 if end of SETUP.

            self.controlDataFlag=False
            if self.type == USBTransaction.CONTROL:
                if self.urbStage==0:
                    self.controlDataFlag=True
                    controlData=buffer[urbLength:]
                    self.setupControl(controlData)
            if self.urbStage!=1:
                self.payloadLength=0
                self.payload=[]
            else:
                self.payload=buffer[urbLength:]
                self.payloadLength=len(self.payload)

            self.initialFlag=True
            self.endFlag=True
            self.mainWriteFlag = (self.direction == USBTransaction.Outbound)
            self.mainReadFlag = (self.direction == USBTransaction.Inbound) 
 
            if self.type == USBTransaction.CONTROL:
                if self.urbStage==0:                    
                    self.endFlag=False
                    #Not at main read or write yet.
                    self.mainWriteFlag = False
                    self.mainReadFlag = False 
                elif self.urbStage==1:
                    self.initialFlag=False
                    self.endFlag=False
                else:
                    self.initialFlag=False
                    self.mainWriteFlag = False
                    self.mainReadFlag = False 

            #For all others, both initial and endflag are true..
            
    def setupControl(self, controlData):
        self.controlData=controlData
        self.bmRequestType=controlData[0]
        self.bRequest=controlData[1]
        self.wValue=debyteifyLittleEndian(controlData[2:4])
        self.wIndex=debyteifyLittleEndian(controlData[4:6])
        self.wLength=debyteifyLittleEndian(controlData[6:8])

#This just sets up all the fields based on a blob of data, given by the list.
#You have to specify urbFormat as Linux or USBPcap.
class USBTransaction(object):
    #Used for .type
    INTERRUPT=0x1
    CONTROL=0x2
    BULK=0x3
    ISOCHRONOUS=0x4
    CUSTOM="CUSTOM"
    END=-1 #used for sentinel trabsaction

    #Used for .direction
    Inbound=1
    Outbound=0

    def __init__(self, data, handle=None, format=Linux, device=None):
        if not isinstance(data, CapturePoint):
            capturePoint=CapturePoint(data, format=format)
            self.captureFormat=format
        else:
            capturePoint=data
            self.captureFormat=capturePoint.format
            
        self.handle=handle
        self.device=device
        self.identityTag=None #This is for Custom types to identify themselves

        self.identityContext={} #This is for parameterized information that should
                                #Be compared for equality.  Convention dicates
                                #This be a dictionary with text keys for all the
                                #parameters.

        self.noteContext={}     #This is for parameterized information that
                                #shouldn't be compared for equality. Convention
                                #dictates this be a dictionary with text keys for  
                                #parameters.                         
                              
        self.filterDecoration=None #Spot for filters to decorate
                                   #the transactions.
                                   #filterDecoration holds data
                                   #for whatever filter processing job you are 
                                   #doing, whereas identityTag is fixed to the
                                   #type.
                                   #filterDecorations would not be part of equality comparison
                                   #identityTag would be.
        self.capturePoints=[]
        if not capturePoint.initialFlag:
            raise CaptureOrderError( "First capture data passed to USBTransaction not beginning of transaction.",
                                      None,
                                      capturePoint )

        #Copy things that do not vary during the transaction
        self.type = capturePoint.type
        self.endPoint = capturePoint.endPoint
        self.direction = capturePoint.direction
        self.deviceID = capturePoint.deviceID
        self.busID = capturePoint.busID

        if (self.type == USBTransaction.CONTROL) and (capturePoint.controlDataFlag):
            self.controlData=capturePoint.controlData
            self.bmRequestType=capturePoint.bmRequestType
            self.bRequest=capturePoint.bRequest
            self.wValue=capturePoint.wValue
            self.wIndex=capturePoint.wIndex
            self.wLength=capturePoint.wLength
            self.direction=capturePoint.direction

        if (self.direction == USBTransaction.Outbound):
            self.writtenData=[]
            self.payload=[]
        if (self.direction == USBTransaction.Inbound):
            self.readData=[]
            self.payload=[]

        self.update(capturePoint)           

    #Define special END transaction used as sentinel value
    #in transaction lists.
    @classmethod
    def makeCustom(cls, identityTag=None, type=None):
        if type==None:
            type=cls.CUSTOM
        transaction=cls.__new__(cls) #Does not call init
        transaction.device=None
        transaction.type = type 
        transaction.identityTag=identityTag
        transaction.identityContext={}
        transaction.noteContext={}
        transaction.captureFormat=None
        transaction.handle=None
        transaction.capturePoints=[]
        transaction.endPoint=None
        transaction.direction=None
        transaction.deviceID=None
        transaction.busID=None
        transaction.completed=True
        transaction.filterDecoration=None
        return transaction
    
    def update( self, data ):
        if not isinstance(data, CapturePoint):
            capturePoint=CapturePoint(data, format=self.captureFormat)
        else:
            capturePoint=data
 
        lastCapturePoint=None
        if len(self.capturePoints) != 0:
            lastCapturePoint=self.capturePoints[-1]
            if self.completed:
                raise ValueError("Tried to add to already complete USBTransaction.")

        if lastCapturePoint != None:
            if (capturePoint.endPoint != lastCapturePoint.endPoint) or \
                (capturePoint.deviceID != lastCapturePoint.deviceID) or \
                (capturePoint.busID != lastCapturePoint.busID):
                raise CaptureOrderError("USBTransaction continue method used when not continuing on same endPoint.",
                                        self,
                                        capturePoint)

        #DO NOT ASSUME that this is start of transaction in any of code, this could be error case.
        #Start grab from fragment
        self.capturePoints.append(capturePoint)
        if (capturePoint.direction == USBTransaction.Outbound) and capturePoint.mainWriteFlag:
            self.writtenData+=capturePoint.payload
            self.payload+=capturePoint.payload
        if (capturePoint.direction == USBTransaction.Inbound) and capturePoint.mainReadFlag:
            self.readData+=capturePoint.payload
            self.payload+=capturePoint.payload
        self.completed=capturePoint.endFlag           
        #END grab from fragment.
        
    def control_direction(self, write=None, read=None ):
        good=True
        readStatus=(self.bmRequestType >> 7) != 0
        if (write != None) and (read != None):
            if read == write:
                raise ValueError("Cannot set write and read to opposite values.")
        good &= (write == None) or (write != readStatus)
        good &= (read == None) or (read == readStatus)
        return good
        
    def control_match( self, *args, **kwArgs):
        control= (self.type==USBTransaction.CONTROL)
        if not control:
            return False

        parameterNames=["bRequest", "wValue", "wIndex", "wLength"]
        parameterLength=len(parameterNames)

        values={} #Ultimately where we store the arguments.
        #Set defaults
        for parameter in parameterNames:
            values[parameter]=None #Set default.

        #We allow first arg to be a variable name, expand that
    
        #We allow args to be sequence objects, unpack that
        #WE also allow textual arguments for variable names, looked
        #up via self.device

        unpackedArgs=[]
        for current in args:
            if isinstance( current, basestring):
                current=self.device.lookupName( current )
            elif not hasattr( current, "__iter__" ): #Convert non sequences to sequenced
                current=[current]
            unpackedArgs += current
         
        argLength=len(unpackedArgs)
        if argLength > len(parameterNames):
            raise TypeError( "control_match() takes at most %s expanded arguments (%s given)" % (parameterLength, argLength ))

        #Update values with unpackedArgs 
        valueIndex=0
        for i in range(len(unpackedArgs)):
            current=unpackedArgs[i]
            values[parameterNames[i]]=current

        #We accept a read or write argument, but not positionally
        values["read" ]=None
        values["write"]=None

        #Update values with kwArgs
        for key in kwArgs.keys():
            if not values.has_key( key ):
                raise TypeError( "control_match got an unexpected keyword argument '%s'" % key )
            if values[key] != None:
                raise TypeError( "control_match got multiple values for keyword argument '%s'" % key )
            values[key]=kwArgs[key]

        #Get values as variables.
        bRequest = values["bRequest"]
        wValue= values["wValue"]
        wIndex= values["wIndex"]
        wLength= values["wLength"]

        #Check balues against self versions.
        good=True
        good &= (bRequest == None) or (bRequest == self.bRequest )
        good &= (wValue == None) or (wValue == self.wValue )
        good &= (wIndex == None) or (wIndex == self.wIndex )
        good &= (wLength == None) or (wLength == self.wLength )
        return good and self.control_direction(write=values["write"], read=values["read"])

#Cannot define this inside class, so I do it here.
USBTransaction.END_TRANSACTION=USBTransaction.makeCustom(type=USBTransaction.END) 

#This creates an iterator for Wireshark Packet Dissections
#dumped as a plain text file, where the Packet Format is "Packet bytes"
#checked only.
#a=DumpWiresharkIterator(fileName) will give you an iterator that each time you
#read from it you will get a python list containing the bytes of the 
#packet
class DumpWiresharkIterator(object):
    #The kwArgs are theree so this can be use in a quicly
    #enumerated list of iterators that are chained together
    #where the parameters for all the settings
    #are passed to all the iterators.
    #
    #data is a filename, but we use the name data so
    #as to not pollute our parameter namespace for 
    #filter chains.
    def __init__(self, data, **kwArgs):
        self.lines=open(data).xreadlines()

    def __iter__(self):
        return self

    def next(self):
        complete=True
        dataRead=False
        packetData=[]
        ignore=False
        while True: #Return is what ends it.
            try:
                line=self.lines.next() 
            except StopIteration,e:
                if dataRead:
                    return packetData
                else:
                    raise StopIteration()

            if line.strip()=="":
                if dataRead:
                    return packetData
                continue
    
            dataRead=True
            
            if line.startswith("Frame"):
                ignore=False
                continue
            if line.startswith("Linux USB Control"):
                ignore=True
                continue
            if ignore:
                continue

            offset=line[0:4]
            numbers=line[6:53]
            numbers=numbers.split()
            for number in numbers:
                value=int(number.strip(),16)
                packetData.append(value)

#This has no error checking so beware.
class DumpVizslaIterator(object):
    #The kwArgs are there so this can be use in a quicly
    #enumerated list of iterators that are chained together
    #where the parameters for all the settings
    #are passed to all the iterators.
    #
    #data is a filename, but we use the name data so
    #as to not pollute our parameter namespace for 
    #filter chains.
    def __init__(self, data, **kwArgs):
        self.lines=open(data).xreadlines()
        self.tripleState=0
        self.tripleBuffer=[]
        self.lineNumber=0
        self.deviceInfo={}
        self.endPointStates={0x0:[USBTransaction.CONTROL, 0, 0, []]} #2nd entry is state. 
                                                                     #0= ready for new command
                                                                     #1= getting data phase.
                                                                     #3rd is direction. which is fixed for all but control
                                                                     #endPoints.
                                                                   #4th is stored triples.
        self.configurations={}
        self.currentConfig=None
        self.interfaceID=0
 
    def __iter__(self):
        return self

    def next(self):
        while True: #Return is what ends it.
            try:
                line=self.lines.next() 
                self.lineNumber += 1
            except StopIteration,e:
                raise StopIteration()

            if line.strip()=="":
                continue

            data=line.split("]", 4)
            if len(data) != 4:
                raise CaptureFormatError("Bad Vizsla capture format")
            data=data[3].strip()
            information=data.split(":",1)
            keyword=information[0].strip()
            if keyword=="":
                continue #Keywordless line.
         
            if self.tripleState==0: 
                if (keyword=="SETUP") or (keyword=="IN") or (keyword=="OUT") or (keyword=="PING"):
                    self.tripleBuffer.append(information)
                    self.tripleState=1 
                    self.tripleStartLineNumber=self.lineNumber 
                else:
                    raise CaptureFormatError("Invalid keyword order");
            elif self.tripleState==1:
                if (self.tripleBuffer[-1][0].strip() != "PING"):
                    if (keyword=="NAK"):
                        self.tripleState=0
                        self.tripleBuffer=[]
                    elif keyword.startswith("DATA"):   
                        self.tripleBuffer.append(information)
                        self.tripleState=2
                    elif (keyword=="STALL"):
                        returnValue=self.processTriple( self.tripleBuffer, self.tripleStartLineNumber )
                        self.tripleState=0
                        self.tripleBuffer=[]
                        if returnValue != None:
                            return returnValue
                    else:
                        raise CaptureFormatError("Invalid keyword order");
                else:
                    if (keyword=="ACK") or (keyword=="NAK") or (keyword=="STALL"):
                        returnValue=self.processTriple( self.tripleBuffer, self.tripleStartLineNumber )
                        self.tripleState=0
                        self.tripleBuffer=[]
                        if returnValue != None:
                            return returnValue
                    else:
                        raise CaptureFormatError("Invalid keyword order");

            elif self.tripleState==2:
                if (keyword=="NAK") or (keyword=="ACK") or (keyword=="NYET"):
                    self.tripleBuffer.append(information)
                    #Okay, we have data to process.
                    returnValue=self.processTriple( self.tripleBuffer, self.tripleStartLineNumber )
                    self.tripleState=0
                    self.tripleBuffer=[]
                    if returnValue != None:
                        return returnValue
                else:
                    raise CaptureFormatError("Invalid keyword order");

                       
    def processTriple(self, tripleBuffer, line):
        transaction = tripleBuffer[0][0].strip()
        target=tripleBuffer[0][1].strip()
        textDeviceID, textEndpoint = target.split(".",2)
        deviceID=int(textDeviceID)
        endPoint=int(textEndpoint)

        lastCommand=tripleBuffer[-1][0].strip()

        #For now we don't worry about NYETS, we assume eventually acked.
        if (lastCommand=="STALL"):
            #Kill transaction
            self.endPointStates[endPoint][1] = 0 #Reset endPoint state.
            self.endPointStates[endPoint][3]=[]
            return None
        elif (lastCommand=="NAK"):
            return None #Don't kill transaction though,
                        #there are cases where it resumes with retry.

        #We also don't worry about PING
        firstCommand=tripleBuffer[0][0].strip()
        if (firstCommand=="PING"):
            return None

        #otherwise it is data.
        textData=tripleBuffer[1][1].strip()
        textBytes=textData.split()
        bytes=[]
        for textByte in textBytes:
            bytes.append( int(textByte, 16) )
        #Drop last 2, it is a CRC.
        bytes=bytes[:-2]

        #Keep track of transactions so we can parse critical ones.
        if transaction == "SETUP":
            self.endPointStates[endPoint][1] = 1 #Setup sent
            self.endPointStates[endPoint][2] = bytes[0]>>7 #Grab direction from bmRequest.
            self.endPointStates[endPoint][3] = [[ transaction, deviceID, endPoint, bytes ]]
            stage=0

        elif len(bytes)==0:    
            #Multiple transaction control over.       
            self.checkForSpecialTransaction( self.endPointStates[endPoint][3] ) 
                                     
            self.endPointStates[endPoint][1] = 0
            self.endPointStates[endPoint][3] = []
            stage=2
        elif self.endPointStates[endPoint][1] == 1:
            self.endPointStates[endPoint][3].append([transaction, deviceID, endPoint, bytes])
            stage=1
        else:
            stage=1
        return self.getCaptureBlock( deviceID, endPoint, bytes, stage, self.tripleStartLineNumber )

    def getCaptureBlock( self, deviceID, endPoint, bytes, stage, lineNumber ):
        #FAKE Vizsla URB definition:
        #  byte 0 is deviceID
        #  byte 1 is endPoint ....bit 7 is set to direction.
        #  byte 2 is type..IE USBTransaaction.CONTROL, etc.
        #  byte 3 is 0 if SETUP, 1 if anything else, 2 for END SETUP/ACK. 
        # byte 4-7 is 32 bit line number
        
        if self.endPointStates.has_key( endPoint ):
            direction = self.endPointStates[endPoint][2]
            urbEndPoint = endPoint
            if direction:
                urbEndPoint |= 0x80
            urb =[ deviceID, urbEndPoint, self.endPointStates[endPoint][0], stage ]
            urb += byteify( lineNumber, 4 )
            return urb+bytes 
        else:
            return None

    def checkForSpecialTransaction(self, packets):
        #We look for the device setup so we can
        #properly instrument captured packets urb.
        #and determine what type of transfer they are.

        #WE are looking for GET_DESCRIPTOR with wValue=2 which
        #enumerates the device configuration, interfaces, and
        #endPoints.
        #
        #We are also looking for SET_CONFIGURATION and SET_INTERFACE
        (transaction, deviceID, endPoint, bytes)= packets[0]

        #Check for special packets.
        if transaction != "SETUP":
            return

        if endPoint!=0:
            return 
        
        bmRequestType=bytes[0]
        bRequest=bytes[1]
        wValue=debyteifyLittleEndian( bytes[2:4] )
        wIndex=debyteifyLittleEndian( bytes[4:6] )
        wLength=debyteifyLittleEndian( bytes[6:8] )
        direction=bmRequestType>>7
        if ((bmRequestType >> 5) & 3) != 0: #Only interested in requests where type=standard.
            return
        recipient=bmRequestType & 0xf;

        #Okay, looking for special GET_DESCRIPTOR first
        if (direction==1) and (recipient==0) and (bRequest==6) and ((wValue>>8)==2): #This is a request for full enumeration.
            enumerationBytes=packets[1][3]
            deviceInfo=self.deviceInfo

            bLength=enumerationBytes[0]
            configurationLength=debyteifyLittleEndian(enumerationBytes[2:4])
            interfaceCount=enumerationBytes[4]
            configID=enumerationBytes[5]
            interfaceBytes=enumerationBytes[bLength:configurationLength]
            configurationInfo = {}
            deviceInfo[ configID ] = configurationInfo

            for j in range( interfaceCount ):
                interfaceID=interfaceBytes[2]
                alternateSetting=interfaceBytes[3]

                endPointCount=interfaceBytes[4]
                endPointBytes=interfaceBytes[9:9+endPointCount*7]
                interfaceInfo = {}
                if j==0:
                    configurationInfo[ 0 ] = interfaceInfo #Set default interface.

                configurationInfo[ (interfaceID, alternateSetting) ]=interfaceInfo

                for k in range( endPointCount ):
                    endPointAddress=endPointBytes[2]
                    transferType=endPointBytes[3] & 3
                    if transferType == 0:
                        cookedType = USBTransaction.CONTROL
                    elif transferType == 1:
                        cookedType = USBTransaction.ISOCHRONOUS
                    elif transferType == 2:
                        cookedType = USBTransaction.BULK
                    elif transferType == 3:
                        cookedType = USBTransaction.INTERRUPT

                    interfaceInfo[ endPointAddress & ~0x80 ]=[endPointAddress, cookedType]
                    endPointBytes=endPointBytes[7:] #Go to next endPoint.
                interfaceBytes=interfaceBytes[9+endPointCount*7:] #Go to next interface
            enumerationBytes=enumerationBytes[configurationLength:] #Go to next configurationa

        #NOW looking for SET_CONFIGURATION and/or SET_INTERFACE
        elif (direction==0) and (recipient==0) and (bRequest==9):
            self.currentConfig=wValue & 0xff
            self.interfaceID=0 #Usually a tuple, but 0 is standin for default interface
            self.setupEndpointStates()
        elif (direction==0) and (recipient==1) and (bRequest==0x11):
            self.interfaceID=(wIndex, wValue & 0xff)
            self.setupEndpointStates()
           
    def setupEndpointStates(self):
         currentState=self.endPointStates[0]

         self.endPointStates={0:[USBTransaction.CONTROL, currentState[1], 0, currentState[3]]}
         interfaceInfo=self.deviceInfo[self.currentConfig][self.interfaceID]
         for endPoint in interfaceInfo.keys():
             #type, direction, state, storedTripleInfo
             data=interfaceInfo[endPoint]
             self.endPointStates[endPoint] = [data[1], 0, data[0]>>7, []]
         #Okay we are completed.


#This is an iterator, which returns CapturePoints as parsed.
class CapturePointIterator( object ):
    #chunkIterator returns binary blobs as received from the packet dumps
    #The logical place to get this is from DumpWiresharkIterator or
    #DumpVizslaIterator.
    #
    #capCounter should be set to 1 below the first numbered 
    #packet of the capture
    #
    #The kwArgs are there so this can be use in a quicly
    #enumerated list of iterators that are chained together
    #where the parameters for all the settings
    #are passed to all the iterators.
    #
    #data is chunk iterator, it gives us lists of bytes that
    #represent each usb captured transaction in the format specified.
    #Note that this will most likely be specifically a DumpIterator
    #instance. We call it data so as not to pollute our namespace
    #of parameter names across all filter chainable iterators.
    def __init__( self, data, format=USBPcap,  capCounter=0, **kwArgs ):
        self.chunkIterator = data
        self.format=format
        self.capCounter=capCounter
        self.capBase=capCounter

    def __iter__(self):
        return self
    
    def next(self):
        chunk=self.chunkIterator.next()
        self.capCounter += 1
        capturePoint=CapturePoint(chunk, format=self.format, capCounter=self.capCounter, capBase=self.capBase)
        return capturePoint

#This returns completed transactions.
#It will not output: 
#   a) uncompleted transactions
#   b) completed transactions whose start is not found
#
#This can also give you a somewhat misleading order of
#events, as this will not output write transactions
#till after they complete successfully, so if multiple
#pipes are in play, the sequencing might get dodgy.
class CompletedTransactionIterator( object ): 
    #the capturePointIterator must return CapturePoints, 
    #CapturePointIterator is the
    #logical choice.
    #
    #The kwArgs are theree so this can be use in a quicly
    #enumerated list of iterators that are chained together
    #where the parameters for all the settings
    #are passed to all the iterators.
    #
    #data is CapturePointIterator, Each call to next gives 
    #us a new capture point.
    #We call it data so as not to pollute our namespace
    #of parameter names across all filter chainable iterators.
    def __init__(self, data, **kwArgs):
        self.capturePointIterator = data

        self.device=valueOrDefault(kwArgs, "device", None)
        self._output = self.generator()

    def __iter__(self):
        return self

    def next(self):
        return self._output.next()

    def generator(self):
        incompleteList=[] #stores in flight transactions.

        while(True): 
            try:
                capturePoint=self.capturePointIterator.next()
            except StopIteration, e:
                #Pad transactions with an end sentinel
                #Which is useful for filtering
                yield  USBTransaction.END_TRANSACTION 
                raise e #Blank means reraise last exception

            success=False
            for transaction in incompleteList:
                try:
                    transaction.update( capturePoint )
                    success=True
                    break
                except CaptureOrderError, e:
                    pass
            if not success:
                try:
                    transaction= \
                        USBTransaction(capturePoint, handle=capturePoint.capCounter, device=self.device)
                except CaptureOrderError, e:
                    #Transaction already in flight. Ignore it. Though it might be nice
                    #To flag this in some cases.
                    continue

                success=True
                incompleteList.append(transaction)

            newIncompleteList=[]
            completedTransaction=None
            for transaction in incompleteList:           
                if transaction.completed:
                    completedTransaction=transaction
                else:
                    newIncompleteList.append(transaction)
            incompleteList=newIncompleteList
            if completedTransaction != None:
                yield completedTransaction 


