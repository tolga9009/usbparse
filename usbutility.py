
def hexdump( packet ):
    value=""
    
    for byte in packet[:-1]:
        value=value+("0x%2.2x, " % byte)
    if len(packet)>=1:
        value=value+("0x%2.2x" % packet[-1])
    return value

#This is for usb commands, which are all mostly little endian
def debyteifyLittleEndian( data ):
    value=0
    for i in  range(len(data)-1, -1, -1):
        value <<= 8
        value |= data[i]
    return value   

#This is big endian version, which is for most of the buffers
#for the remote device
def debyteify( data ):
    value =0
    for i in range(len(data)):
        value <<= 8
        value |= data[i]
    return value 

#The mask sets what bits need to match,
#All 3 fields must be the same length.
def buffer_match( dataA, dataB, mask ):
    if len(dataA) != len(dataB):
        return False
    if len(mask) != len(dataA):
        raise ValueError("Mask must be the same length as first buffer")
    for i in range(len(dataA)):
        if (dataA[i] & mask[i]) != (dataB[i] & mask[i]):
            return False
    return True

def valueOrDefault( map, key, default ):
    if map.has_key(key):
        return map[key]
    return default


