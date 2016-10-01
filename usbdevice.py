import usbparse
from usbparse import USBTransaction
from usbutility import debyteify, hexdump, buffer_match, valueOrDefault
import usbfilter
import sys

#Define a usb device
class Device( object ):
    def __init__(self, registers={}, filterParameters={}):
        #We do not need to cjange anything in filterParameters,
        #which is what the argument is for--modifying.

        self.registers=registers
        self.names={}
        self.names.update(registers)
        self._reverseRegisters = self._build_reverse_lookup( self.registers )
 
    def reverseRegisterLookup(self,  lookupValues ): 
        return self._reverseLookup( self._reverseRegisters, lookupValues )

    def lookupName( self, name ):
        value=self.names[ name ]
        #Strip off mask check
        if hasattr(value[-1], "__iter__"):
            value=value[:-1]
        return value

    def _build_reverse_lookup( self, source ):
        destination={}
        for name, values in source.items():

            mask=0 #Anything & -1 is anything
            nextValue=0
            if hasattr( values[-1], "__iter__" ): #Has mask specification
               (mask, nextValue)=values[-1]
               values=values[:-1]

            currentDestination=destination
            for i in range(len(values)-1):
                key = values[i]
                if not currentDestination.has_key( key ):
                    currentDestination[key]={}
                currentDestination=currentDestination[key]
                if not isinstance( currentDestination, {}.__class__ ):
                    raise RuntimeError( "Register Conflict" )
            key=values[-1]
            if not currentDestination.has_key( key ):
                currentDestination[key]=[]
            definition = (name, values, mask, nextValue)
            if definition in currentDestination[key]:
                raise RuntimeError( "Register Conflict" )
            currentDestination[key].append( definition )
        return destination

    def _maskCheck( self, current, nextValue=None ):
        testNextValue=nextValue
        if nextValue==None:
            testNextValue=0
        for (name, values, mask, confirmValue) in current:
            if (testNextValue & mask) == confirmValue:
                #potential match
                if not (nextValue==None and (mask !=0)): #Don't find if mask specified
                                                        #and we have no nextValue
                    return (name, values)
        return None #No mask match found

    def _reverseLookup( self, reverseStructure, lookupValues ):
        current=reverseStructure
        for i in range(len(lookupValues)):
            key = lookupValues[i]
            if not isinstance( current, {}.__class__ ):
                return self._maskCheck( current, key )
            if not current.has_key(key):
                return None
            current=current[key]
        if isinstance( current, {}.__class__ ):
            return None
        return self._maskCheck(current) #This will be an object, not a dictionary at this point
         
#This is not a filter, but a configuration for a filter chain
class DeviceFilterConfiguration( object ):
    def __init__( self, device, filterClassChain, additionalFilterParameters={} ):
        self.device=device
        self.filterChain=filterClassChain
        self.filterParameters.update( additionalFilterParameters )

    #startData is an iteratable.
    def getFiltered(startData, passedFilterParameters):
        finalFilterParameters={}
        finalFilterParameters.update(self.filterParameters)
        finalFilterParameters.update(passedFilterParameters)

        #setup filter chain
        currentData=startData
        for iteratorCls in self.filterChain:
            currentData=iteratorCls( currentData, **finalFilterParameters )
        return currentData #Returns iterable object.



