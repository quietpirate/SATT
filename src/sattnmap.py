#!/usr/bin/env python

import os
import subprocess
import xml.etree.ElementTree as ET
import random
import yaml

def parseNmapXml(filename):
    liveHosts = []
    tree = ET.parse(filename)
    root = tree.getroot()
    for host in root.findall('host'):
        for status in host.findall('status'):
            state = status.get('state')
            for address in host.findall('address'):
                addressType = address.get('addrtype')
                if addressType == "ipv4":
                    address = address.get('addr')
                    if state == "up":
                        liveHosts.append(address)
    return liveHosts

def host_discovery(targetRange, viewpoint, outputName, excludeHosts):
    icmpList = []
    nonicmpList = []
    fullList = []
    print "starting icmp"
    p = subprocess.Popen("sudo nmap --reason -d -sn --stats-every 10s -n -PE --exclude " + excludeHosts + " -oA ./discovery/" + outputName + "_icmp " + targetRange, shell=True)
    p.communicate()

    print "starting ack"
    subprocess.check_output("sudo nmap --reason -d -sn --stats-every 10s -n -PA7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157 --initial-rtt-timeout 5ms --exclude " + excludeHosts + " -oA ./discovery/" + outputName + "_ack " + targetRange, shell=True)

    print "starting syn"
    subprocess.check_output("sudo nmap --reason -d -sn --stats-every 10s -n -PS391,910,1328,1999,2583,2813,5078,7282,7563,7772,8829,9576,9802,9803,10153,11603,12266,12307,12941,12963,13638,14159,15028,15613,16484,18365,19639,20301,20647,21102,21779,22275,22678,22906,25542,25886,27803,28570,28595,30191,32378,32510,33946,34310,34340,38877,39634,39816,40558,43286,45270,46126,46313,47580,48837,49110,49377,49381,51655,54703,54973,55825,55905,56163,58870,59219,59260,61169,61837,63277,63794,63819,64663,64995 --exclude " + excludeHosts + " --initial-rtt-timeout 5ms -oA ./discovery/" + outputName + "_syn " + targetRange, shell=True)

    liveHosts = parseNmapXml("./discovery/" + outputName + "_icmp.xml")
    for host in liveHosts:
        if host not in icmpList:
            icmpList.append(host)
            print "Added host:" + host

    if len(icmpList) > 0:
        print "Writing icmp hosts to: icmp_hosts.txt"
        icmp_hosts = open('./discovery/icmp_hosts.txt', 'w')
        for host in icmpList:
            icmp_hosts.write("%s\n" % host)
        icmp_hosts.close()


    liveHosts = parseNmapXml("./discovery/" + outputName + "_ack.xml")
    for host in liveHosts:
        if host not in nonicmpList:
            nonicmpList.append(host)
            print "Added host:" + host

    if len(nonicmpList) > 0:
        print "Writing ack hosts to: non-icmp_hosts.txt"
        non_icmp_hosts = open('./discovery/non_icmp_hosts.txt', 'w')
        for host in nonicmpList:
            non_icmp_hosts.write("%s\n" % host)
        non_icmp_hosts.close()


    liveHosts = parseNmapXml("./discovery/" + outputName + "_syn.xml")
    for host in liveHosts:
        if host not in nonicmpList:
            nonicmpList.append(host)
            print "Added host:" + host

    if len(nonicmpList) > 0:
        print "Writing syn hosts to file non-icmp_hosts.txt"
        non_icmp_hosts = open('./discovery/non_icmp_hosts.txt', 'w')
        for host in nonicmpList:
            non_icmp_hosts.write("%s\n" % host)
        non_icmp_hosts.close()

    fullList = icmpList + list(set(nonicmpList) - set(icmpList))
    if len(fullList) > 0 :
        full_hosts = open('./scripts/targets.txt', 'w')
        for host in fullList:
            full_hosts.write("%s\n" % host)
        full_hosts.close()

    return fullList

def findRTT(targetIP, fullList):
    while True:
        try:
            response = subprocess.check_output("ping -c 5 " + targetIP, shell=True)
            break


        except subprocess.CalledProcessError:
            print "Failed to ping " + targetIP + "."
            targetIP = random.choice(fullList)
            print "Choosing new IP: " + targetIP + " to ping\n"
            continue

    index = response.find("rtt")
    rttString = response[index:]
    rttTimes = rttString.split("/")
    firstString = rttTimes[3]
    minRTT = firstString[7:]
    avgRTT = rttTimes[4]
    maxRTT = rttTimes[5]
    print response + "\nMinRTT: " + minRTT + "\nAvgRT: " + avgRTT + "\nMaxRTT: " + maxRTT + "\n"
    return minRTT, avgRTT, maxRTT

def tcpScans(targetRange, viewpoint, initialRTT, tcpMaxRTT, outputName, tcpMaxHostGroup, tcpMinHostGroup, maxRetries, minRate, excludeHosts):
    if viewpoint == 'internal':
        print "Starting internal TCP Port scan"
        p = subprocess.Popen("sudo nmap -d -Pn --stats-every 10s -n --reason -sT --max-hostgroup " + tcpMaxHostGroup + " --min-hostgroup " + tcpMinHostGroup + " --max-retries " + maxRetries + " --min-rate " + minRate + " -p T:0-65535 --max-scan-delay 25ms --exclude " + excludeHosts + " --max-rtt-timeout "+ tcpMaxRTT + "ms --initial-rtt-timeout "+ initialRTT + "ms -oA ./tcp/" + outputName + "_tcp -iL ./scripts/targets.txt", shell=True)
        p.communicate()
    else:
        print "Starting external TCP Port scan"
        p = subprocess.Popen("sudo nmap -d -Pn --stats-every 10s --reason -sT --max-hostgroup 2 --min-hostgroup 2 --max-retries 7  --max-scan-delay 25ms -p T:0-65535  --max-rtt-timeout "+ tcpMaxRTT + "ms --initial-rtt-timeout "+ initialRTT + "ms -oA ./tcp/" + outputName + "_tcp -iL ./scripts/targets.txt", shell
        =True)
        p.communicate()
    print "TCP scanning done."
    return True

def udpScans(targetRange, viewpoint, initialRTT, udpMaxRTT, outputName, udpMaxHostGroup, udpMinHostGroup, udpMaxRetries, minRate, excludeHosts):
    if viewpoint == 'internal':
        print "Starting internal UDP Port scan"
        p = subprocess.Popen("sudo nmap -d -Pn --reason --stats-every 10s --top-ports 5000 -sUV -n --max-retries " + udpMaxRetries + " --min-hostgroup " + udpMinHostGroup + " --max-hostgroup " + udpMaxHostGroup + " --version-intensity 0 --exclude " + excludeHosts + " --max-rtt-timeout " + udpMaxRTT + "ms --max-scan-delay 25ms --initial-rtt-timeout "+ initialRTT + "ms -oA ./udp/" + outputName + "_udp -iL ./scripts/targets.txt", shell=True)
        p.communicate()

    else:
        print "Starting external UDP Port scan"
        p = subprocess.Popen("sudo nmap --reason -d -Pn --stats-every 10s --top-ports 3000 -sUV --max-retries "+ udpMaxRetries +" --version-intensity 0 --max-rtt-timeout " + udpMaxRTT + " --initial-rtt-timeout " + initialRTT + " -oA ./udp/" + outputName + "_udp -iL ./scripts/targets.txt", shell=True)
        p.communicate()

    print "UDP scanning done."
    return True

def givenTarget(targetRange, sourceIP, viewpoint, configFile):
    config = open(configFile, "r")
    settings = yaml.load(config)

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

    outputName = sourceIP + "_to_" + targetRange.replace("/","-")
    fullList = host_discovery(targetRange, viewpoint, outputName, excludeHosts)
    if len(fullList) == 0:
        print "No hosts found, exiting..."
        exit()
    pingTarget = random.choice(fullList)
    print "Choosing: " + pingTarget + " to ping\n"

    minRTT, avgRTT, maxRTT = findRTT(pingTarget, fullList)

    if initialRTT == None:
        avgRTT = str(float(avgRTT) + 10)
    else:
        avgRTT = initialRTT
    if tcpMaxRTT == None:
        tcpMaxRTT = str(float(maxRTT) + 1000)
    if udpMaxRTT == None:
        udpMaxRTT = str(float(maxRTT) + 100)
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
        min_rate = "100"
    if excludeHosts == None:
        excludeHosts = ""

    tcpscanning = tcpScans(targetRange, viewpoint, avgRTT, tcpMaxRTT, outputName, tcpMaxHostGroup, tcpMinHostGroup, maxRetries, min_rate, excludeHosts)
    udpscanning = udpScans(targetRange, viewpoint, avgRTT, udpMaxRTT, outputName, udpMaxHostGroup, udpMinHostGroup, maxRetries, min_rate, excludeHosts)
    if tcpscanning == True and udpscanning == True:

        print "Nmap scanning completed. Exiting..."
        exit()


if __name__ == "__main__":
   main(sys.argv[1:])
