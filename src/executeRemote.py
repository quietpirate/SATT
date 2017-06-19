#!/usr/bin/env python


import sys, getopt
import os
import subprocess
import yaml
import fabfile
import sattnmap
import socket

def get_ip_address(hostname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((hostname, 80))
    return s.getsockname()[0]


def getDiscoveryScans(targetRange, outputName, excludeHosts):

    #Discovery Scans
    icmp = "nmap --reason -d -sn --stats-every 10s -n -PE --exclude " + excludeHosts + " -oA /home/smpentest/nmap/"+ outputName + "/discovery/" + outputName + "_icmp " + targetRange

    #Ack Scans
    ack = "nmap  --reason -d -sn --stats-every 10s -n -PA7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157 --initial-rtt-timeout 5ms --exclude " + excludeHosts + " -oA /home/smpentest/nmap/"+ outputName + "/discovery/" + outputName + "_ack "+ targetRange

    #Syn Scans
    syn = "nmap --reason -d -sn --stats-every 10s -n -PS391,910,1328,1999,2583,2813,5078,7282,7563,7772,8829,9576,9802,9803,10153,11603,12266,12307,12941,12963,13638,14159,15028,15613,16484,18365,19639,20301,20647,21102,21779,22275,22678,22906,25542,25886,27803,28570,28595,30191,32378,32510,33946,34310,34340,38877,39634,39816,40558,43286,45270,46126,46313,47580,48837,49110,49377,49381,51655,54703,54973,55825,55905,56163,58870,59219,59260,61169,61837,63277,63794,63819,64663,64995 --exclude " + excludeHosts + " --initial-rtt-timeout 5ms -oA /home/smpentest/nmap/"+ outputName + "/discovery/" + outputName + "_syn " + targetRange

    return icmp, ack, syn,

def getTCPUDPScans(targetRange, viewpoint, avgRTT, tcpMaxRTT, outputName, tcpMaxHostGroup, tcpMinHostGroup, maxRetries, minRate, excludeHosts, udpMaxRTT, udpMaxHostGroup, udpMinHostGroup):
    #Run TCP Scan
    tcp = "nmap -d -Pn --stats-every 10s -n --reason -sT --max-hostgroup " + tcpMaxHostGroup + " --min-hostgroup " + tcpMinHostGroup + " --max-retries " + maxRetries + " --min-rate " + minRate + " -p T:0-65535 --max-scan-delay 25ms --exclude " + excludeHosts + " --max-rtt-timeout "+ tcpMaxRTT + "ms --initial-rtt-timeout "+ avgRTT + "ms -oA /home/smpentest/nmap/"+ outputName + "/tcp/" + outputName + "_tcp " + targetRange

    #Run UDP Scan
    udp = "nmap -d -Pn --reason --stats-every 10s --top-ports 5000 -sUV -n --max-retries " + maxRetries + " --min-hostgroup " + udpMinHostGroup + " --max-hostgroup " + udpMaxHostGroup + " --version-intensity 0 --exclude " + excludeHosts + " --max-rtt-timeout " + udpMaxRTT + "ms --max-scan-delay 25ms --initial-rtt-timeout "+ avgRTT + "ms -oA /home/smpentest/nmap/"+ outputName + "/udp/" + outputName + "_udp " + targetRange

    return tcp, udp


def nmap(targetRange, sourceIP, viewpoint, configFile):
    configFile = os.path.join(os.path.dirname(__file__), '..', 'config.yml')
    config = open(configFile, "r")
    settings = yaml.load(config)
    beaconUser = settings["typeProperties"]["user"]
    beaconIP = settings["typeProperties"]["beaconIP"]
    tcpMaxRTT = settings["nmapProperties"]["tcpMaxRTT"]
    udpMaxRTT = settings["nmapProperties"]["udpMaxRTT"]
    initialRTT = settings["nmapProperties"]["initial-rtt-timeout"]
    tcpMaxHostGroup = settings["nmapProperties"]["tcpMaxHostGroup"]
    tcpMinHostGroup = settings["nmapProperties"]["tcpMinHostGroup"]
    maxRetries = settings["nmapProperties"]["max-retries"]
    udpMaxHostGroup = settings["nmapProperties"]["udpMaxHostGroup"]
    udpMinHostGroup = settings["nmapProperties"]["udpMinHostGroup"]
    min_rate = settings["nmapProperties"]["min-rate"]
    excludeHosts = settings["nmapProperties"]["exclude-hosts"]
    printCommands = settings["sattProperties"]["printCommands"]
    outputName = sourceIP + "_to_" + targetRange.replace("/","-")

    icmp, ack, syn = getDiscoveryScans(targetRange, outputName, excludeHosts)
    fabfile.getDiscoveryCommands(icmp, ack, syn)

    if initialRTT == None:
        avgRTT = str(float(avgRTT) + 10)
    else:
        avgRTT = initialRTT
    if tcpMaxRTT == None:
        tcpMaxRTT = str(float(maxRTT) + 10)
    if udpMaxRTT == None:
        udpMaxRTT = str(float(maxRTT) + 25)
    if tcpMaxHostGroup == None:
        tcpMaxHostGroup = "2"
    if tcpMinHostGroup == None:
        tcpMinHostGroup = "2"
    if maxRetries == None:
        maxRetries = "7"
    if udpMaxHostGroup == None:
        udpMaxHostGroup = "16"
    if udpMinHostGroup == None:
        udpMinHostGroup = "16"
    if min_rate == None:
        min_rate = "1"
    if excludeHosts == None:
        excludeHosts = beaconIP


    tcp, udp = getScans(targetRange, viewpoint, avgRTT, tcpMaxRTT, outputName, tcpMaxHostGroup, tcpMinHostGroup, maxRetries, min_rate, excludeHosts, udpMaxRTT, udpMaxHostGroup, udpMinHostGroup)

    fabfile.getTCPUDPCommands(tcp, udp)
    hostIP = get_ip_address(targetRange)
    fabfile.tarAndExfol(hostIP)

    return
