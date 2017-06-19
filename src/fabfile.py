from fabric.api import *
import sys, getopt
import os
import yaml
import subprocess
import getpass

def getBeaconUserAndIP():
    configFile = os.path.join(os.path.dirname(__file__), '..', 'config.yml')
    config = open(configFile, "r")
    settings = yaml.load(config)

    beaconUser = settings["typeProperties"]["user"]
    beaconIP = settings["typeProperties"]["beaconIP"]

    return beaconUser, beaconIP


def makeFiles():
    print "Creating files"
    beaconUser, beaconIP = getBeaconUserAndIP()

    env.shell = "/bin/bash -l -c"
    env.user = beaconUser

    scope = open("scope.yml", "r")
    scopeConfigs = yaml.load(scope)
    perspective = scopeConfigs["perspective"]["internal"]["beacon"][0]["ip"]
    subnetList = scopeConfigs["subnets"]

    command = "mkdir ~/nmap"
    execute(filesOnBeacon, hosts=beaconIP, command=command)

    for i in range(0, len(subnetList)):
        subnet = scopeConfigs["subnets"][i]
        subnetRange = subnet.get('subnet')
        dirName = (str(perspective) + "_to_" + str(subnetRange)).replace("/", "-")
        path = "nmap/" + dirName
        command = "mkdir ~/nmap/" + dirName + " && mkdir ~/nmap/" + dirName + "/tcp && mkdir ~/nmap/" + dirName + "/udp && mkdir ~/nmap/" + dirName + "/scripts && mkdir ~/nmap/" + dirName + "/discovery"
        execute(filesOnBeacon, hosts=beaconIP, command=command)
    return



def filesOnBeacon(command):
    run(command)

def getDiscoveryCommands(icmp,ack,syn):
    beaconUser, beaconIP = getBeaconUserAndIP()
    env.shell = "/bin/bash -l -c"
    env.user = beaconUser

    nmapCommands= [icmp, ack, syn]
    for commandType in nmapCommands:
        execute(runNmaps, hosts=beaconIP, command=commandType)
    return

def getTCPUDPCommands(tcp,udp):
    beaconUser, beaconIP = getBeaconUserAndIP()
    env.shell = "/bin/bash -l -c"
    env.user = beaconUser

    nmapCommands= [tcp, udp]
    for commandType in nmapCommands:
        execute(runNmaps, hosts=beaconIP, command=commandType)

    return

def runNmaps(command):
    sudo(command, user="root")

def tarAndExfol(hostIP):
    beaconUser, beaconIP = getBeaconUserAndIP()
    env.shell = "/bin/bash -l -c"
    env.user = beaconUser
    hostUser = getpass.getuser()
    commandToRun = "tar -czf nmap_"+beaconIP+".tar nmap/ && scp nmap_" + beaconIP + ".tar "+ hostUser + "@" + hostIP+":~/"

    execute(filesOnBeacon, hosts=beaconIP, command=commandToRun)


if __name__ == '__main__':
    main()
