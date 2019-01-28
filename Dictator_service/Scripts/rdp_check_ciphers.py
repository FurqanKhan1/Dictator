import socket
import sys
import binascii


# assign arguments
host = sys.argv[1]
port = int(sys.argv[2])


# Packets
X224_CONNECTION_REQUEST = "\x03\x00\x00\x2c\x27\xe0\x00\x00\x00\x00\x00\x43\x6f\x6f\x6b\x69\
\x65\x3a\x20\x6d\x73\x74\x73\x68\x61\x73\x68\x3d\x65\x6c\x74\x6f\
\x6e\x73\x0d\x0a\x01\x00\x08\x00%s\x00\x00\x00" 

CLIENT_MCS_CONNECT_INTIAL = "\x03\x00\x01\x9c\x02\xf0\x80\x7f\x65\x82\x01\x90\x04\x01\x01\x04\
\x01\x01\x01\x01\xff\x30\x19\x02\x01\x22\x02\x01\x02\x02\x01\x00\
\x02\x01\x01\x02\x01\x00\x02\x01\x01\x02\x02\xff\xff\x02\x01\x02\
\x30\x19\x02\x01\x01\x02\x01\x01\x02\x01\x01\x02\x01\x01\x02\x01\
\x00\x02\x01\x01\x02\x02\x04\x20\x02\x01\x02\x30\x1c\x02\x02\xff\
\xff\x02\x02\xfc\x17\x02\x02\xff\xff\x02\x01\x01\x02\x01\x00\x02\
\x01\x01\x02\x02\xff\xff\x02\x01\x02\x04\x82\x01\x2f\x00\x05\x00\
\x14\x7c\x00\x01\x81\x26\x00\x08\x00\x10\x00\x01\xc0\x00\x44\x75\
\x63\x61\x81\x18\x01\xc0\xd4\x00\x04\x00\x08\x00\x00\x05\x20\x03\
\x01\xca\x03\xaa\x09\x08\x00\x00\x28\x0a\x00\x00\x45\x00\x4d\x00\
\x50\x00\x2d\x00\x4c\x00\x41\x00\x50\x00\x2d\x00\x30\x00\x30\x00\
\x31\x00\x34\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\
\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x01\xca\x01\x00\x00\x00\x00\x00\
\x10\x00\x07\x00\x01\x00\x37\x00\x36\x00\x34\x00\x38\x00\x37\x00\
\x2d\x00\x4f\x00\x45\x00\x4d\x00\x2d\x00\x30\x00\x30\x00\x31\x00\
\x31\x00\x39\x00\x30\x00\x33\x00\x2d\x00\x30\x00\x30\x00\x31\x00\
\x30\x00\x37\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x04\xc0\x0c\x00\x09\x00\x00\x00\
\x00\x00\x00\x00\x02\xc0\x0c\x00%s\x00\x00\x00\x00\x00\x00\x00\
\x03\xc0\x2c\x00\x03\x00\x00\x00\x72\x64\x70\x64\x72\x00\x00\x00\
\x00\x00\x80\x80\x63\x6c\x69\x70\x72\x64\x72\x00\x00\x00\xa0\xc0\
\x72\x64\x70\x73\x6e\x64\x00\x00\x00\x00\x00\xc0"

X224_NATIVE_RDP = "\x03\x00\x00\x27\x22\xe0\x00\x00\x00\x00\x00\x43\x6f\x6f\x6b\x69\
\x65\x3a\x20\x6d\x73\x74\x73\x68\x61\x73\x68\x3d\x61\x64\x6d\x69\
\x6e\x69\x73\x74\x72\x0d\x0a"

# Error messages
error_messages = {}
error_messages["\x01"] = "SSL_REQUIRED_BY_SERVER"
error_messages["\x02"] = "SSL_NOT_ALLOWED_BY_SERVER"
error_messages["\x03"] = "SSL_CERT_NOT_ON_SERVER"
error_messages["\x04"] = "INCONSISTENT_FLAGS"
error_messages["\x05"] = "HYBRID_REQUIRED_BY_SERVER"


# Supported encryption protocols, methods and levels
enc_protocols = {"\x00" : ["Native RDP", False], "\x01" : ["SSL", False], "\x03" : ["CredSSP", False]}
enc_methods = {"\x01" : ["40-bit RC4", False], "\x02" : ["128-bit RC4", False], "\x08" : ["56-bit RC4", False], "\x10" : ["FIPS 140-1", False]}
enc_levels = {"\x00" : ["None", False], "\x01" : ["Low", False], "\x02" : ["Client Compatible", False], "\x03" : ["High", False], "\x04" : ["FIPS 140-1", False]}


# Received errors
errors = {}


# Enumerate supported protocols
for n in enc_protocols.keys():
    packet = X224_CONNECTION_REQUEST % n
    #print binascii.hexlify(n)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.send(packet)
    response = s.recv(1024)

    if (response[3] == "\x0b"):
        enc_protocols["\x00"][1] = True
        break
    else:
        if (response[11] == "\x02"):
            enc_protocols[n][1] = True
        else:
            errors[response[15]] = True
    
    #print binascii.hexlify(response)
    
    s.close()


print
print "===================="
print "ENCRYPTION PROTOCOLS"
print "===================="

print
print "Supported"
print "---------"

for n in enc_protocols.keys():
    if (enc_protocols[n][1]):
        print enc_protocols[n][0]

print 
print "Unsupported"
print "-----------"

for n in enc_protocols.keys():
    if (not enc_protocols[n][1]):
        print enc_protocols[n][0]

print 
print "Received error messages"
print "-----------------------"

for error in errors.keys():
    print error_messages[error]

if (len(errors) == 0):
    print "None"


# Enumerate native RDP encryption methods and levels
if (enc_protocols["\x00"][1]):
    
    for n in enc_methods.keys():
        first_packet = X224_NATIVE_RDP
        second_packet = CLIENT_MCS_CONNECT_INTIAL % n
        #print "Request: ", binascii.hexlify(n)

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            s.send(first_packet)
            response = s.recv(1024)
            
            #print binascii.hexlify(response)
            sys.stdout.flush()
            s.send(second_packet)
            response = s.recv(1024)
        except socket.error:
            s.close()
            continue

        #print binascii.hexlify(response)
        for i in range(0, len(response)):
            if (response[i:i+2] == "\x02\x0c"):
                #print "Recevied: ", binascii.hexlify(response[i+4])
                #print "Level: ", binascii.hexlify(response[i+8])
                enc_methods[response[i+4]][1] = True
                enc_levels[response[i+8]][1] = True
                break
        
        s.close()
        

    print "\n"
    print "====================="
    print "NATIVE RDP ENCRYPTION"
    print "====================="
    
    print
    print "Supported encryption methods"
    print "----------------------------"

    for n in enc_methods.keys():
        if (enc_methods[n][1]):
            print enc_methods[n][0]

    print 
    print "Unsupported encryption methods"
    print "------------------------------"

    for n in enc_methods.keys():
        if (not enc_methods[n][1]):
            print enc_methods[n][0]

    print 
    print "Server encryption level"
    print "-----------------------"

    for n in enc_levels.keys():
        if (enc_levels[n][1]):
            print enc_levels[n][0]


        


