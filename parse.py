
import sys
import os
import usbparse
from usbparse import USBTransaction, DumpIterator, CapturePointIterator, CompletedTransactionIterator
from usbparse import CaptureFormatError
from usbutility import hexdump, debyteify
import elgato
import usbfilter
import traceback

###############
#Configuration#
###############

#Specify filename as only parameter at command line

#Device:, Choose one.
#deviceFilterConfiguration=elgato.GameCaptureHDNewDump
deviceFilterConfiguration=elgato.GameCaptureHDDump

#set appropriately to the 1 below first numbered packet of capture
#to match wireshark numbers.
capCounter=0 

#Use to change the filename output in the dump for capCounterDisplay
filenameProxy=None #Use this if you want the output to list a 
                   #different filename than you input, for cap
                   #counter display

#Display comments that show what capture packet # and filename each usb transaction came from
capCounterDisplay=False

#Autodetection format list.
formats=[usbparse.USBPcap, usbparse.Linux] #Make this just one if autodetect screws up.
                                           #It is possible it won't be caught on the first
                                           #packet..
######
#CODE#
######
filename=sys.argv[1]

if filenameProxy==None:
    filenameProxy=os.path.basename(filename)

for formatIndex in range(len(formats)):
    format=formats[formatIndex]

    filterParameters={
                       "format":format,
                       "capCounter":capCounter,
                       "capCounterDisplay":capCounterDisplay,
                       "filenameProxy":filenameProxy,
                     }
    filterParameters.update( deviceFilterConfiguration.filterParameters )

    inputConfiguration=usbfilter.ConvertDumpFileToCompletedTransactions

    inputTransactions=inputConfiguration.getFiltered( filename, filterParameters )
    output=deviceFilterConfiguration.getFiltered( inputTransactions, filterParameters )

    try:
        for transaction in output:
            if transaction.filterDecoration != None:
                print transaction.filterDecoration
    except CaptureFormatError, e:
        if formatIndex == len(formats)-1:
            raise e
        else:
            continue
    sys.exit(0) #Parse success!

