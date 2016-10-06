import usbparse
from usbparse import USBTransaction
from usbutility import debyteify, hexdump, buffer_match, valueOrDefault

#Define filter interface. implemented by default as pass-through
#filter is more than just any old iterator, it specifically works
#on USBTransactions. DumpIterator and CapturePointIterators are not filters.
#Furthermore filters typically just a subclass that implements a
#new filter method.
class Filter(object):
    #Make sure subclasses supercall this, or 
    #don't define new __init__.
    #
    #The kwArgs argument is there so this can be used in a quick filterchain setup...
    #where each filter in the chain may be passed multiple arguments, and we need
    #to accept parameters not for us.
    #
    #data is transaction iterator, Each call to next gives 
    #us a new transaction.
    #We call it data so as not to pollute our namespace
    #of parameter names across all filter chainable iterators.
    def __init__(self, data, **kwArgs):
        self.input = data
        self.output=self.feedThroughGenerator()

        #This is necessary even though we don't have a 
        #superclass so we can work with multiple inheritance.
        #chaining.
        super( Filter, self ).__init__(data, **kwArgs)
 
    def feedThroughGenerator(self):   
        while True:
            inputTransaction=self.input.next()
            outputTransactions=self.filter(inputTransaction)
            for transaction in outputTransactions:
                yield transaction

    def __iter__( self ):
        return self

    def next(self):
        return self.output.next()

    #In most cases for subclasses this would be the only function to
    #change.
    def filter(self, transaction): #Make any internally cached data is
                                   #Dumped if transaction.type==USBTransaction.End
        return [transaction]

#Define GeneratorFilter abstract class. implemented by default as pass-through
#This is a Filter that use a python generator, via subclasing and 
#implementing the filterGenerator method.  
class GeneratorFilter(Filter):
    #Make sure subclasses supercall this, or 
    #don't define new __init__.
    #
    #The kwArgs argument is there so this can be used in a quick filterchain setup...
    #where each filter in the chain may be passed multiple arguments, and we need
    #to accept parameters not for us.
    #
    #data is transaction iterator, Each call to next gives 
    #us a new transaction.
    #We call it data so as not to pollute our namespace
    #of parameter names across all filter chainable iterators.
    def __init__(self, data, **kwArgs):
        super( GeneratorFilter, self).__init__( data, **kwArgs )
        self.filterGeneratorReset()

    #This runs the filter_generator, not feeding into it anything
    #ignored by the ignore method.
    def filter(self, transaction):
        try:            
            self.transactionList.append(transaction)
            #Do not allow USBTransaction.END to be ignored by
            #simple ignore filters..
            if transaction.type != USBTransaction.END:
                if self.ignore( transaction ):
                    self.deferredIgnoreList.append(transaction)
                    return []

            value=self.filterGenerator.send(transaction)
            if value == None:
                if transaction.type == USBTransaction.END:
                    raise StopIteration() #Wow it swallowed that.
                return []

            else:
                try:
                    self.filterGenerator.next() #Go to generator end,
                except StopIteration, e:
                    returnValue=value + self.deferredIgnoreList
                    self.filterGeneratorReset()
                    if transaction.type == USBTransaction.END:
                        returnValue += [parseusb.USB_END_TRANSACTION]
                    return returnValue
                raise RuntimeError( "Ill behaved filter_generator" )

        except StopIteration, e:
            #Failed filter.
            returnValue=self.transactionList
            self.filterGeneratorReset()
            return returnValue
 
    def filterGeneratorReset(self):
        self.transactionList=[]
        self.deferredIgnoreList=[]
        self.filterGenerator=self.filter_generator()
        self.filterGenerator.send(None)

    #In most cases for subclasses this would be only function to change 
    def filterGenerator(self): #Passthrough filter default. override in subclass
        transaction=yield None
        yield [transaction] #gotta end once you yield a list.
        return  
     
    def ignore( self, transaction ): #Ignore nothing default, override in subclass
        return False       

#Now for some helper stuff.

#Abstract mixin class for python multiple inheritance to enable display of 
#CapCounter. Mix in to a filter object to be able to get capInfo
class CapCounterDecorator( object ):
    def __init__(self, data, **kwargs):
        self.filenameProxy=valueOrDefault(kwargs, "filenameProxy", None)
        self.capCounterDisplay=valueOrDefault(kwargs, "capCounterDisplay", True)
        super(CapCounterDecorator, self).__init__()

    #Use this when you need it.
    def capInfo( self, transaction ):
        returnValue=""
        if self.capCounterDisplay:
            returnValue+="[[Cap %s" % transaction.handle
            if self.filenameProxy != None:
                returnValue += " from %s" % self.filenameProxy
            returnValue+="]]" 
        return returnValue

#Define Filter to inherit for generator filters
#to ignores bulk packets not related to control flow
class IgnoreBulkGeneratorFilter( GeneratorFilter ):
    def ignore(self, transaction):
        if ( transaction.type == USBTransaction.CONTROL ) or \
           ( transaction.type == USBTransaction.INTERRUPT ) or \
           ( transaction.type == USBTransaction.CUSTOM ) :
            return False
        return True

#This is a useful filter to adds textual strings for each of the transactions
#based on how they would be represented as *simple* commands
#IE filterDecoration for a 2 byte usb control write
#becomes: write_config<uint16_t>(bRequest, wValue, wIndex, writeValue)
class BasicCommandTextFilter( Filter, CapCounterDecorator ):
    #The kwargs argument is there so this can be used in a quick filterchain setup...
    #where each filter in the chain may be passed multiple arguments, and we need
    #to accept parameters not for us.
    #data must be a transaction iterator, but we use data as the name, so
    #as not to pollute the namespace of names for the filterChain
    def __init__(self, data,  **kwargs):
        self.reverseRegisterLookup=valueOrDefault(kwargs, "reverseRegisterLookup", None)
        super( BasicCommandTextFilter, self).__init__(data, **kwargs)

    typeList=[(1, 8),
              (2, 16),
              (4, 32),
              (float('inf'), None)]
    
    @classmethod
    def findTypeTuple( cls, length ):
        index=0
        while length > cls.typeList[index][0]:
            index+=1
        return cls.typeList[index]    

    @staticmethod
    def typeFunctionName( prefix, typeTuple ):
        if typeTuple[1]==None:
            return prefix+"_buffer"
        else:
            return prefix+"<uint%d_t>" % typeTuple[1]

    @staticmethod
    def typeExtraArguments( length, bufferName, typeTuple ):
        returnString=""
        if typeTuple[1]==None:
            returnString+=", %s" % bufferName
        if length != typeTuple[0]:
            returnString+=", %d" % length
        return returnString

    @staticmethod
    def typeParameterize( data, typeTuple, bufferPrefix="" ):
        if typeTuple[1]==None:
            return bufferPrefix+"{"+hexdump(data)+"}"
        else:
            byteLength=typeTuple[0]
            format="0x%%%d.%dx" % (byteLength*2, byteLength*2) #each hex digit is one nybble.
            return format % debyteify( data )

    def outputParameters( self, device, parameters, formatParameters ):
        returnValue=""
        if device != None:
            register=device.reverseRegisterLookup( parameters )
            if register != None:
                name, valueList=register
                parameters=parameters[len( valueList ):]
                formatParameters=formatParameters[len( valueList ):]
                if len(parameters) != 0:
                    returnValue += "%s, " % name
                else:
                    returnValue += "%s" % name
        formatting=", ".join( formatParameters )
        returnValue += formatting % tuple(parameters)
        return returnValue
    
    @staticmethod
    def textDirection( transaction ):
        lookup={ transaction.Inbound:"INBOUND",
                 transaction.Outbound:"OUTBOUND" }
        return lookup[ transaction.direction ]

    def filter(self, transaction):
        if transaction.type==USBTransaction.INTERRUPT:
            if transaction.direction==transaction.Inbound:
                transaction.filterDecoration="\tinterruptPend();" 
                capInfo = self.capInfo(transaction)
                if capInfo != "":
                    transaction.filterDecoration+=" //%s" % self.capInfo(transaction)
            else:
                transaction.filterDecoration="\t//INTERRUPT %s %s" % (self.textDirection(transaction), self.capInfo(transaction))

        elif transaction.type==USBTransaction.BULK:
            transaction.filterDecoration="\t//BULK TRANSFER %s %s" % (self.textDirection(transaction), self.capInfo(transaction))
        elif transaction.type==USBTransaction.CONTROL:

            if (transaction.bmRequestType >> 5 ) & 3 != 2:
                return [] #Ignore all transactions that are not
                          #Vendor transactions. IE, filter out
                          #Setup and control stuff.

            read=(transaction.bmRequestType >> 7) != 0

            length=transaction.wLength;
            typeTuple=self.findTypeTuple(length)

            if read:
                printString= "\t%s(" % self.typeFunctionName( "read_config", typeTuple )

                parameters=[ transaction.bRequest, transaction.wValue, transaction.wIndex ]
                formatParameters=[ "0x%2.2x", "0x%4.4x", "0x%4.4x" ]
                printString += self.outputParameters(transaction.device, 
                                                     parameters,
                                                     formatParameters)
                    
                printString += "%s);" % self.typeExtraArguments( length, "readBuffer", typeTuple )
                printString += " //EXPECTED=%s " % self.typeParameterize( transaction.readData, typeTuple );
                printString += self.capInfo(transaction)
            else:
                assert (transaction.wLength == len(transaction.writtenData))
                printString= "\t%s("  % self.typeFunctionName( "write_config", typeTuple )

                parameters=[ transaction.bRequest, transaction.wValue, transaction.wIndex ]
                formatParameters=[ "0x%2.2x", "0x%4.4x", "0x%4.4x" ]
                printString += self.outputParameters(transaction.device,
                                                     parameters,
                                                     formatParameters)
 
                inlineData=self.typeParameterize( transaction.writtenData, typeTuple, "VC" ) #VC is a macro we use
                                                                                             #stands for vector of characters.
                printString += ", %s);" % inlineData
                capInfo=self.capInfo(transaction)
                if capInfo != "":
                    printString += " //%s" % capInfo
            transaction.filterDecoration=printString
        return [transaction]

#This is not a filter, but a configuration for a filter chain
class FilterConfiguration( object ):
    def __init__( self, filterClassChain, filterParameters={} ):
        self.filterChain=filterClassChain
        self.filterParameters=filterParameters #Make sure all filterConfigurations
                                               #get passed this, including
                                               #inputConfiguration that may be
                                               #before this.

    #startData is an iteratable.
    def getFiltered( self, startData, filterParameters):

        #setup filter chain
        currentData=startData
        for iteratorCls in self.filterChain:
            currentData=iteratorCls( currentData, **filterParameters )
        return currentData #Returns iterable object.

#Here's a FilterConfiguration  that turns an input text file into transactions
ConvertWiresharkDumpFileToCompletedTransactions=FilterConfiguration( 
    filterClassChain = [ usbparse.DumpWiresharkIterator, 
                         usbparse.CapturePointIterator,
                         usbparse.CompletedTransactionIterator ]
)

ConvertVizslaDumpFileToCompletedTransactions=FilterConfiguration(
    filterClassChain = [ usbparse.DumpVizslaIterator, 
                         usbparse.CapturePointIterator,
                         usbparse.CompletedTransactionIterator ]
)


