import usbparse
from usbparse import USBTransaction
from usbutility import debyteify, hexdump, buffer_match

from usbfilter import Filter, IgnoreBulkGeneratorFilter
from usbfilter import BasicCommandTextFilter, CapCounterDecorator
from usbfilter import FilterConfiguration

from usbdevice import Device
import elgato_registers

#defines filters and device information for Elgato GameCaptureHD and GameCaptureHDNew
#devices.
#############################################################################
# FILTERS                                                                   #
#############################################################################
#This must go in filter chain before any MailWrite, MailRead, DoEnableFindFilter, or ScmdFilter,
#to catch every read and write. 
#
#it tracks the reads and writes to ENABLE_REGISTER and MAIL_SEND_ENABLE_REGISTER_STATE,
#So we know if things changed or not.
class EnableRegistersReadWriteFilter(Filter, CapCounterDecorator):
    #The kwArgs argument is there so this can be used in a quick filterchain setup...
    #where each filter in the chain may be passed multiple arguments, and we need
    #to accept parameters not for us.
    #
    #data is transaction iterator, Each call to next gives 
    #us a new transaction.
    #We call it data so as not to pollute our namespace
    #of parameter names across all filter chainable iterators.
    def __init__( self, data, **kwArgs ):
        self.values=[ None, None ] #ENABLE_REGISTER, MAIL_SEND_ENABLE_REGISTER_STATE
        self.enableValue=None
        super( EnableRegistersReadWriteFilter, self).__init__( data, **kwArgs )
 
    def filter(self, transaction):
        valueIndex=None
        if transaction.control_match("MAIL_SEND_ENABLE_REGISTER_STATE", 2):
            valueIndex=1
            mask= ~0xd080 #d080 gets autoset on HDNew devices for MAIL_SEND_ENABLE_REGISTER_STATE
        elif transaction.control_match("ENABLE_REGISTER", 2):
            valueIndex=0
            mask= ~0xd080 #d080 gets autoset on HDNew devices for MAIL_SEND_ENABLE_REGISTER_STATE
        else:
            return [transaction] #No filter.

        newValue = debyteify( transaction.payload )

        value=self.values[valueIndex]
        transaction.noteContext["previous"]=value
        transaction.noteContext["current"]=newValue
        changed=value != newValue
        transaction.noteContext["changed"]=changed

        if transaction.control_direction( read=True):
            if (value != None) and ((newValue & mask) != (value & mask)):
                if valueIndex==1:
                    raise RuntimeError( "MAIL_SEND_ENABLE_REGISTER_STATE changed on its own, mind blown.")
                else:
                    raise RuntimeError( "ENABLE_REGISTER changed on its own, mind blown.")
            #if valueIndex==1: #Replace actual read text
            #    transaction.filterDecoration="\treadEnableState(); //EXPECTED 0x%4.4x %s" % (newValue, self.capInfo(transaction))
        #else:
            #if not changed and (valueIndex==1): 
            #    transaction.filterDecoration="\twriteEnableState(); //EXPECTED WRITE 0x%4.4x %s" % (newValue, self.capInfo(transaction))
        self.values[valueIndex]=newValue
        return [transaction]

#This should only go into filter chain directly after EnableStateChangeReadWriteFilter
#to catch every read and write. 
#It pairs writes and readbacks of the state change register and 
#turns them into a doEnable call.
class DoEnableFilter(IgnoreBulkGeneratorFilter, CapCounterDecorator):
    def filter_generator(self):
        #Match first command
        transaction=yield None
        firstTransaction=transaction

        if not transaction.control_match( "MAIL_SEND_ENABLE_REGISTER_STATE", 2, write=True ):
            return 

        #If you get an exception here it is because you didnt put 
        #EnableRegistersReadWriteFilter in the filterchain before this.
        previousState=transaction.noteContext["previous"]
        newState=transaction.noteContext["current"]

        transaction=yield None
        if not transaction.control_match( "ENABLE_REGISTER", 2, write=True ):
            return 
        previousEnable=transaction.noteContext["previous"]
        newEnable=transaction.noteContext["current"]

        transaction=yield None
        if not transaction.control_match( "MAIL_SEND_ENABLE_REGISTER_STATE", 2, read=True ):
            return 
        readState=transaction.noteContext["current"]

        transaction=yield None
        if not transaction.control_match( "ENABLE_REGISTER", 2, read=True ):
            return 
        readEnable=transaction.noteContext["current"]

        if (newState != readState) or (newEnable != readEnable):
            raise RuntimeError( "doEnable readbacks do not match writes, mind blown.")

        newSetMask=newState & ~previousState #pulls bits that went to 1 in state
        changedEnables = (newEnable ^previousEnable)
        newSetMask |= changedEnables #In order to change enables the setmask has to be set.
        valueMask=newEnable & newSetMask
        unsanctionedChanges = ~newState & changedEnables
        
        processorOff=(newEnable & 0x2)==0

        if unsanctionedChanges and (not processorOff):
            raise RuntimeError( "doEnable behaviour not actually understood, mind blown.")
        
        printString= "doEnable( UNKNOWN | 0x%4.4x, 0x%4.4x);" % (newSetMask, valueMask)
        #Todo, I may need to handle None values in the future.
        printString += " //state %4.4x->%4.4x, enable %4.4x->%4.4x" % \
            (previousState, newState, previousEnable, newEnable)

        capInfo=self.capInfo( firstTransaction )
        if capInfo != "":
            printString += " %s" % capInfo

        newTransaction = USBTransaction.makeCustom( "doEnable" )
        newTransaction.identityContext = { "previousState":previousState, "newState":newState,
                                           "previousEnable":previousEnable, "newEnable":newEnable }
        newTransaction.filterDecoration = "\t%s" % printString
        yield [newTransaction]

class HDScmdFilter(IgnoreBulkGeneratorFilter, CapCounterDecorator):
    def filter_generator(self):
        #Match first command
        transaction=yield None
        firstTransaction=transaction

        if not transaction.control_match( "SCMD_REGISTER", 6, write=True ):
            return 
        command=transaction.payload[2]
        mode=transaction.payload[3]
        send=debyteify(transaction.payload[4:6])

        fCommand="0x%2.2x" % command #formatted command
        fSend = "0x%4.4x" % send #formatted send
        if command == 1:
            fCommand="SCMD_IDLE"
        elif command == 4:
            fCommand="SCMD_RESET"
        elif command == 4:
            fCommand="SCMD_INIT"
        elif command == 5:
            fCommand="SCMD_STATE_CHANGE"
            if send == 1:
                fSend="SCMD_STATE_STOP"
            elif send == 2:
                fSend="SCMD_STATE_START"
            elif send == 4:
                fSend="SCMD_STATE_NULL"

        printString= "scmd(%s, 0x%2.2x, %s);" % (fCommand, mode, fSend);

        capInfo=self.capInfo( firstTransaction )
        if capInfo != "":
            printString += " //%s" % capInfo

        newTransaction = USBTransaction.makeCustom( "scmd" )
        newTransaction.identityContext = { "command":command, "mode":mode, "send":send }
        newTransaction.filterDecoration = "\t%s" % printString
        yield [newTransaction]

#Probably should make this share some code with above
class HDNewScmdFilter(IgnoreBulkGeneratorFilter, CapCounterDecorator):
    def filter_generator(self):
        #Match first command
        transaction=yield None
        firstTransaction=transaction

        if not transaction.control_match( "SCMD_REGISTER", 4, write=True ):
            return 
        command=transaction.payload[0]
        mode=transaction.payload[1]
        send=debyteify(transaction.payload[2:4])

        fCommand="0x%2.2x" % command #formatted command
        fSend = "0x%4.4x" % send #formatted send
        if command == 1:
            fCommand="SCMD_IDLE"
        elif command == 4:
            fCommand="SCMD_INIT"
        elif command == 5:
            fCommand="SCMD_STATE_CHANGE"
            if send == 1:
                fSend="SCMD_STATE_STOP"
            elif send == 2:
                fSend="SCMD_STATE_START"
            elif send == 4:
                fSend="SCMD_STATE_NULL"

        #There are other commands we get...we just haven't identified them
        if (command == 1) or (command == 4) or (command == 5): #These on the other hand...
            if (mode & 0xa0) and ((mode & 0xa0) != 0xa0):
                raise RuntimeException("Here's a chance to figure what mode in scmd bits mean")
                                       
            if not (mode & 0xa0): #One of these two bits I think disables interrupts.
                transaction=yield None
                if not(transaction.type==USBTransaction.INTERRUPT):
                    raise RuntimeError("Unexpectedly no interrupt for scmd.")
                    return
                
                modeChanged=False
                while not modeChanged:
                    transaction=yield None
                    #scmd state readback register
                    if not transaction.control_match("HDNEW_SCMD_READBACK_REGISTER", 2, read=True):
                        raise RuntimeError("Unexpected exit from scmd.")
                        return
                    if transaction.payload[0] == command:
                        modeChanged=True

        #And now we are done
        printString= "scmd(%s, 0x%2.2x, %s);" % (fCommand, mode, fSend);

        capInfo=self.capInfo( firstTransaction )
        if capInfo != "":
            printString += " //%s" % capInfo

        newTransaction = USBTransaction.makeCustom( "scmd" )
        newTransaction.identityContext = { "command":command, "mode":mode, "send":send }
        newTransaction.filterDecoration = "\t%s" % printString
        yield [newTransaction]

class SparamFilter(Filter, CapCounterDecorator):
    def filter(self, transaction):
        valueIndex=None
        if not transaction.control_match("SEND_H264_TRANSCODER_BITFIELD", wLength=8, write=True):
            return [transaction] #Filter does not apply
 
        value=debyteify( transaction.payload[0:4] )
        mask=debyteify( transaction.payload[4:8] )
        maskMinusLowest=mask & (mask-1) #bit trick, clears lowest bit
                                        #of mask.
        
        lowBit=mask-maskMinusLowest 
        if lowBit==0:
            #No bits set. This is weird enough I'd like to throw a runtime error.
            raise RuntimeError( "NOP SPARAM that processes zero bits found, mind blown.")
        lsb=lowBit.bit_length()-1
        rightMask=mask >> lsb
        bitCount=rightMask.bit_length()
        
        originalValue=value>>lsb

        #well now we have lsb and bitcount, now for sanity checks.
        regeneratedMask = ((1<<bitCount)-1)<<lsb

        if (regeneratedMask != mask) or ((value & mask) != value ):
            #This is an atypical SETUP_H264_TRANSCODER_BITFIELD write, this is 
            #weird enough I want to raise an error
            raise RuntimeError( "Non-SPARAM write to SETUP_H264_TRANSCODER_FIELD found, mind blown.")
        #Also make sure we don't ever run over a 16 bit boundary...
        wordIndex=lsb//16
        wordIndexTop=(lsb+bitCount-1)//16
        if wordIndex != wordIndexTop:
            raise RuntimeError( "SPARAM write runs over 16 bit boundary, mind blown.")
        port=transaction.wIndex
        if (wordIndex==0):
            port+=2
        else:
            lsb-=16 #Gotta shift

        #Lookup to see if known
        lookupValues=[port, lsb, bitCount]
        name=transaction.device.reverseTranscoderBitfieldLookup( lookupValues ) 
        if name == None:
            returnString="\tsparam( 0x%4.4x, %d, %d, %d );" % (port, lsb, bitCount, originalValue);
        else:
            returnString="\tsparam( %s, %d );" % (name[0], originalValue)

        capInfo=self.capInfo(transaction);
        if capInfo!="":
            returnString += " //%s" % self.capInfo(transaction);
        transaction.filterDecoration=returnString
        return [transaction]

class SlsiFilter(Filter, CapCounterDecorator):
    def filter(self, transaction):
        valueIndex=None
        if not transaction.control_match("SEND_H264_TRANSCODER_WORD", wLength=2, write=True):
            return [transaction] #Filter does not apply
 
        value=debyteify( transaction.payload )
        
        returnString="\tslsi( 0x%4.4x, %4.4x );" % (transaction.wIndex, value);

        capInfo=self.capInfo(transaction);
        if capInfo!="":
            returnString += " //%s" % self.capInfo(transaction);
        transaction.filterDecoration=returnString
        return [transaction]

class HDNewMailWriteFilter(IgnoreBulkGeneratorFilter, CapCounterDecorator):
    def filter_generator(self):
        #Match first command
        transaction=yield None
        firstTransaction=transaction
        if not transaction.control_match( "HDNEW_MAIL_WRITE", write=True ):
            return
        payload=transaction.payload
            
        #Check 2nd command
        transaction=yield None
        if not transaction.control_match( "HDNEW_MAIL_REQUEST_CONFIGURE", 4, write=True ):
            return
        setup=transaction.payload
        if not buffer_match( setup, [0x9, 0x0, 0x0, 0x0], [0xff, 0xff, 0x01, 0x00]):
            return 
        port= setup[2]>>1
        length=setup[3]
        if  len(payload) != (length +1 ) & ~1: #padded to even boundary.
            return
        payload = payload[:length] #Trim paddded byte if necessary.

        #3rd transaction is an interrupt
        transaction=yield None
        if transaction.type != USBTransaction.INTERRUPT:
            return
                
        transaction=yield None
        if not transaction.control_match( "HDNEW_INTERRUPT_STATUS", 2, read=True ):
            return
            
        mailReady=False
        while not mailReady: 
            transaction=yield None
            if not transaction.control_match( "MAIL_REQUEST_READY", 2):
                return
            mailReady=(transaction.payload[1] & 1) #good is there to prevent evaluation of 2nd term
                
        transaction=yield None
        if not transaction.control_match( "HDNEW_MAIL_READ", 2, read=True ):
            return
        
        transaction=yield None
        if not transaction.control_match( "MAIL_SEND_ENABLE_REGISTER_STATE", 2, write=True ):
            return
        if (transaction.noteContext.has_key("changed") and transaction.noteContext["changed"]):
            #I think we can safely say we are in a mailWrite here.
            raise RuntimeError( "MAIL_SEND_ENABLE_REGISTER_STATE changed inside mailWrite, mind blown.")

        mailReady=False
        while not mailReady: 
            transaction=yield None
            if not transaction.control_match( "MAIL_REQUEST_READY", 2):
                return
            mailReady=(transaction.payload[1] & 1) #good is there to prevent evaluation of 2nd term
     
        printString= "mailWrite( 0x%2.2x, VC{" % port
        for i in range(len(payload)-1):
            printString+= "0x%2.2x, " % payload[i]
        if len(payload)>0:
            printString+= "0x%2.2x" % payload[-1]
        printString += "} );"

        capInfo=self.capInfo( firstTransaction )
        if capInfo != "":
            printString += " //%s" % capInfo

        newTransaction = USBTransaction.makeCustom( "hdNewWrite" )
        newTransaction.identityContext = { "payload":payload, "port":port }
        newTransaction.filterDecoration = "\t%s" % printString
        
        yield [ newTransaction ] #Substitute transactions.
 
class HDNewMailReadFilter(IgnoreBulkGeneratorFilter, CapCounterDecorator):
    def filter_generator(self):
        #1st command
        transaction=yield None
        firstTransaction=transaction
        if not transaction.control_match( "HDNEW_MAIL_REQUEST_CONFIGURE", write=True ):
            return
        setup=transaction.payload
        if not buffer_match( setup, [0x9, 0x1, 0x0, 0x0], [0xff, 0xff, 0x01, 0x00]):
            return 
        port= setup[2]>>1
        length=setup[3]
        paddedSize=2+length+(length & 1)

        #2nd transaction is an interrupt
        transaction=yield None
        if transaction.type != USBTransaction.INTERRUPT:
            return
                
        transaction=yield None
        if not transaction.control_match( "HDNEW_INTERRUPT_STATUS", 2, read=True ):
            return
            
        mailReady=False
        while not mailReady: 
            transaction=yield None
            if not transaction.control_match( "MAIL_REQUEST_READY", 2):
                return
            mailReady=(transaction.payload[1] & 1) #good is there to prevent evaluation of 2nd term
                
        transaction=yield None
        if not transaction.control_match( "HDNEW_MAIL_READ", paddedSize, read=True ):
            return
        
        payload=transaction.readData[2:2+length]
        
        printString= "mailRead( 0x%2.2x, %d );" % (port, length)
        printString+=" //EXPECTED {%s}" % hexdump(payload)
        capInfo=self.capInfo( firstTransaction )
        if capInfo != "":
            printString += " %s" % capInfo

        newTransaction = USBTransaction.makeCustom( "hdNewRead" )
        newTransaction.identityContext = { "payload":payload, "port":port }
        newTransaction.filterDecoration = "\t%s" % printString
        
        yield [ newTransaction ] #Substitute transactions.
 
class HDMailWriteFilter(IgnoreBulkGeneratorFilter, CapCounterDecorator):
    def filter_generator(self):
        #Match first command
        transaction=yield None
        firstTransaction=transaction
        if not transaction.control_match( "HD_MAIL_REGISTER", write=True ):
            return
        port = transaction.wIndex >> 8
        payload=transaction.payload

        mailReady=False
        while not mailReady: 
            transaction=yield None
            #Technically this could have a changed state, but we've audited, it
            #Just stores the previously set state here.
            if not transaction.control_match( "MAIL_SEND_ENABLE_REGISTER_STATE", 2, write=True ):
                return
            if (transaction.noteContext.has_key("changed") and transaction.noteContext["changed"]):
                #I think we can safely say we are in a mailWrite here.
                raise RuntimeError( "MAIL_SEND_ENABLE_REGISTER_STATE changed inside mailWrite, mind blown.")

            transaction=yield None
            if not transaction.control_match( "MAIL_REQUEST_READY", 2):
                return
            mailReady=(transaction.payload[1] & 1) #good is there to prevent evaluation of 2nd term
           
        printString= "mailWrite( 0x%2.2x, VC{" % port
        for i in range(len(payload)-1):
            printString+= "0x%2.2x, " % payload[i]
        if len(payload)>0:
            printString+= "0x%2.2x" % payload[-1]
        printString += "} );"
        capInfo=self.capInfo( firstTransaction )
        if capInfo != "":
            printString += " //%s" % capInfo

        newTransaction = USBTransaction.makeCustom( "hdWrite" )
        newTransaction.identityContext = { "payload":payload, "port":port }
        newTransaction.filterDecoration = "\t%s" % printString
        
        yield [ newTransaction ] #Substitute transactions.

class HDMailReadFilter(IgnoreBulkGeneratorFilter, CapCounterDecorator):
    def filter_generator(self):
        #Match first command
        transaction=yield None
        firstTransaction=transaction
        if not transaction.control_match( "HD_MAIL_REGISTER", read=True ):
            return
        port = transaction.wIndex >> 8
        payload=transaction.payload
        length=transaction.wLength;
            
        printString= "mailRead( 0x%2.2x, %d );" % (port, length)
        printString+=" //EXPECTED {%s}" % hexdump(payload)

        capInfo=self.capInfo( firstTransaction )
        if capInfo != "":
            printString += " %s" % capInfo

        newTransaction = USBTransaction.makeCustom( "hdNewRead" )
        newTransaction.identityContext = { "payload":payload, "port":port }
        newTransaction.filterDecoration = "\t%s" % printString
        
        yield [ newTransaction ] #Substitute transactions.

#Not sure what this really does, but 0xbc, 0x0800, 0x2008 appears to have
#some lock bits that are checked.
class CompleteStateChangeFilter(IgnoreBulkGeneratorFilter, CapCounterDecorator):
    def filter_generator(self):
        oldTransaction=None
        firstTransaction=None

        stateChangeComplete=False;
        while(True):
            transaction=yield None
            if not transaction.control_match( "SCMD_STATE_READBACK_REGISTER", 2, read=True ):
                return
            if firstTransaction == None:
                firstTransaction=transaction

            olderTransaction=oldTransaction
            oldTransaction=transaction

            transaction=yield None
            if not transaction.control_match( "SCMD_STATE_CHANGE_COMPLETE", 2, read=True ):
                if transaction.control_match( "SCMD_STATE_READBACK_REGISTER", 2, read=True ):
                    if not stateChangeComplete:
                        raise RuntimeError( "Unexpected behaviour of GetStreamStatusChange, examine behaviour." )
                    break
                else:
                    return
            else:
                if stateChangeComplete:
                    raise RuntimeError( "Unexpected behaviour of GetStreamStatusChange, examine behaviour." )
            stateChangeComplete=(debyteify(transaction.payload) & 0x4 > 0)

            transaction=yield None
            if not transaction.control_match( 0xbc, 0x0900, 0x01b0, 2, read=True ):
                return

        if olderTransaction == None:
            return #Fragment, just got two reads from SCMD_STATE_READBACK_REGISTER in a row, didn't
                   #go through the loop once   
        

        changeOldest=debyteify(transaction.payload)
        changeOld=debyteify(transaction.payload)
        change=debyteify(transaction.payload)
        if (change != changeOld) or (changeOld != changeOldest):
            raise RuntimeError( "Unexpected transient change, examine behaviour." )

        transaction=yield None
        if not transaction.control_match( "SCMD_STATE_CHANGE_COMPLETE", 2, write=True ):
            return
        if debyteify(transaction.payload) != 4:
            raise RuntimeError( "Unexpected write value !=4, mind blown" )

        transaction=yield None
        if not transaction.control_match( 0xbc, 0x0900, 0x01b0, 2, write=True ):
            return
        if debyteify(transaction.payload) != 0:
            raise RuntimeError( "Unexpected write value != 0, mind blown." )

 
        printString= "\tcompleteStateChange(); //EXPECTED 0x%4.4x %s" % (change, self.capInfo( firstTransaction ))

        newTransaction = USBTransaction.makeCustom( "GetStreamStatusChange" )
        newTransaction.identityContext = { "change":change }
        newTransaction.filterDecoration = printString
        
        yield [ newTransaction ] #Substitute transactions.



#############################################################################
# Devices                                                                   #
#############################################################################
class ElgatoGameCaptureDevice( Device ):
    def __init__(self, registers={}):
        super( ElgatoGameCaptureDevice, self).__init__(registers)

        self.transcoderBitFields=elgato_registers.transcoder_bit_fields
        self.names.update(self.transcoderBitFields)

        self._reverseTranscoderBitFields = self._build_reverse_lookup( self.transcoderBitFields )

    def reverseTranscoderBitfieldLookup(self,  lookupValues ): 
        return self._reverseLookup( self._reverseTranscoderBitFields, lookupValues )

GameCaptureHDNew=ElgatoGameCaptureDevice( elgato_registers.HDNew_registers );
GameCaptureHD=ElgatoGameCaptureDevice( elgato_registers.HD_registers );

#############################################################################
# Device Filter Configurations                                              #
#############################################################################
GameCaptureHDNewDump=FilterConfiguration(
    filterClassChain=[BasicCommandTextFilter, 
                      EnableRegistersReadWriteFilter, DoEnableFilter,
                      HDNewScmdFilter,
                      SparamFilter, SlsiFilter,
                      CompleteStateChangeFilter,
                      HDNewMailWriteFilter, HDNewMailReadFilter],
    filterParameters={ "device":GameCaptureHDNew }
)
   
GameCaptureHDDump=FilterConfiguration(
    filterClassChain= [BasicCommandTextFilter, 
                       EnableRegistersReadWriteFilter, DoEnableFilter,
                       HDScmdFilter,
                       SparamFilter, SlsiFilter,
                       CompleteStateChangeFilter,
                       HDMailWriteFilter, HDMailReadFilter],
    filterParameters={ "device":GameCaptureHD }
)

