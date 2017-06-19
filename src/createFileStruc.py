#!/usr/bin/env python


import sys, getopt
import os
import yaml
import subprocess
import fabric



def createFiles():
    scope = open("scope.yml", "r")
    scopeConfigs = yaml.load(scope)
    perspective = scopeConfigs["perspective"]["subnet"]
    subnetList = scopeConfigs["subnets"]
    print perspective, subnetList
    for i in range(0, len(subnetList)):
        subnet = scopeConfigs["subnets"][i]
        subnetRange = subnet.get('subnet')
        dirName = (str(perspective) + "_to_" + str(subnetRange)).replace("/", "-")
        path = "automated/nmap/" + dirName
        if not os.path.exists(path):
            os.makedirs(path)
            os.makedirs(path + "/tcp")
            os.makedirs(path + "/udp")
            os.makedirs(path + "/discovery")
            os.makedirs(path + "/scripts")




if __name__ == '__main__':
    filesOnBeacon()
