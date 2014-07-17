import time
import platform
from socket import socket
import sys
from optparse import OptionParser

hostname = platform.node().split('.')[0]
filtered_ports = ''

STATE = {
    '01':'ESTABLISHED',
    '02':'SYN_SENT',
    '03':'SYN_RECV',
    '04':'FIN_WAIT1',
    '05':'FIN_WAIT2',
    '06':'TIME_WAIT',
    '07':'CLOSE',
    '08':'CLOSE_WAIT',
    '09':'LAST_ACK',
    '0A':'LISTEN',
    '0B':'CLOSING'
    }

class AutoVivification(dict):

    def __getitem__(self, item):
        try:
            return dict.__getitem__(self, item)
        except KeyError:
            value = self[item] = type(self)()
            return value


def hex2dec(x):
    return str(int(x,16))

def loadTcp():
    file = open('/proc/net/tcp', 'r')
    data = file.readlines()
    file.close()

    # Remove first line of headers
    data.pop(0)
    return data

def parseData(data, incl_listen=True):
    # return a list of tuples - port number and state.
    parsed = []
    for line in data:
             line_list = line.split(' ')
             # Remove all of the empty list items.
             line_list = filter(None, line_list)
             local_port = hex2dec(line_list[1].split(':')[1])
             state = STATE[line_list[3]]
             if incl_listen:
                 parsed.append((local_port, state))
             else:
                 if state != 'LISTEN':
                     parsed.append((local_port, state))
    return parsed

def filterResults(data, ports):
    filtered = []
    for item in data:
        if item[0] in ports:
            filtered.append(item)
    return filtered

def sumStates(data):

    frequencies = AutoVivification()

    for item in data:
        port = item[0]
        state = item[1]
        if frequencies[port].has_key(state):
            frequencies[port][state]['count'] += 1
        else:
            frequencies[port][state]['count'] = 1
    return frequencies

def formMessage(freq_dict):
    lines = []
    now = int( time.time() )
    for port in freq_dict.iterkeys():
        for state in freq_dict[port].iterkeys():
            lines.append("hosts.%s.tcp.%s.%s %s %d" % (hostname, port, state, freq_dict[port][state]['count'], now))
    message = '\n'.join(lines) + '\n'
    return message

def sendToGraphite(host, port, message):
    sock = socket()
    try:
        sock.connect( (host, port) )
        sock.sendall(message)
        sock.close()
    except:
        print "Couldn't connect to %(server)s on port %(port)d, is carbon-agent.py running?" % { 'server':host, 'port':port }
        sys.exit(1)

if __name__ == '__main__':

    parser = OptionParser()
    parser.add_option("-H", "--host", dest="host", help="specify carbon host", metavar="HOST")
    parser.add_option("-p", "--port", dest="port", help="specify carbon port", metavar="PORT")

    (options, args) = parser.parse_args()
    required_ports = args
 
    # Load data from /proc/net/tcp and parse what we are interested in.
    data = parseData(loadTcp())
    # Only Filter if ports are passed to script
    if required_ports:
        data = filterResults(data, required_ports)
    # Total the port / state combinations.
    freq = sumStates(data)
    # Form the dot delimited message with count and time for carbon.
    message = formMessage(freq)

    # Send the message to the carbon port.
    if options.host and options.port:
        sendToGraphite(options.host, int(options.port), message)
    else:
        print message
        print "You must specify a host and port to send metrics to graphite and redact the output above."

  


