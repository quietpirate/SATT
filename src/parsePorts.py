#!/usr/bin/env python

import yaml
import sys
import glob, os

def parsePorts():
    ipList = []
    udpPortList = []
    tcpPortList = []
    with open('portscan.yml', 'r') as stream:
        dataLoaded = yaml.load(stream)
        length = len(dataLoaded)
        for x in range(0, length):
            width = len(dataLoaded[x]["hosts"])
            for y in range(0,width):
                ipList.append(dataLoaded[x]["hosts"][y]["ip"])
                portData = dataLoaded[x]["hosts"][y]["ports"]
                p = len(portData)
                for u in range(0, p):
                    if  dataLoaded[x]["hosts"][y]["ports"][u][1] == "udp" and dataLoaded[x]["hosts"][y]["ports"][u][1] not in udpPortList:
                        udpPortList.append(dataLoaded[x]["hosts"][y]["ports"][u][0])
                    if  dataLoaded[x]["hosts"][y]["ports"][u][1] == "tcp" and dataLoaded[x]["hosts"][y]["ports"][u][1] not in tcpPortList:
                        tcpPortList.append(dataLoaded[x]["hosts"][y]["ports"][u][0])
    udpPortList = list(set(udpPortList))
    tcpPortList = list(set(tcpPortList))
    tcpPorts = ','.join(str(e) for e in tcpPortList)
    udpPorts = ','.join(str(e) for e in udpPortList)

    with open('./scripts/scan-ports.txt', 'w') as portfile:
        portfile.write("T:" + tcpPorts + "\n")
        portfile.write("U:" + udpPorts+ "\n")
    print "Done"
    return
