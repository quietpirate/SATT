import subprocess, os
import yaml

def runNSEs(targetRange, sourceIP, outputName, maxRetries, maxRTT):
    with open("./scripts/scan-ports.txt", "r") as portlist:
        ports = portlist.read()
    ports = ports.replace('\n', ',').rstrip(',')
    p = subprocess.Popen('sudo nmap --reason -Pn --stats-every 10s -d -n --max-retries ' + maxRetries + ' -p '+ ports + ' -sTV -sUV -A --script="((default or vuln or safe or discovery) and not (targets-ipv6-map4to6 or brute or auth or fuzzer or external or url-snarf or targets-ipv6-wordlist or dos or http-slowloris* or targets-xml or broadcast)) or (ftp-anon)" --script-timeout 600 --max-rtt-timeout ' + maxRTT + 'ms -oA ./scripts/' + outputName + '_scripts -iL ./scripts/targets.txt', shell=True)
    p.communicate()
    return


def nseMain(targetRange, sourceIP, configFile):
    config = open(configFile, "r")
    settings = yaml.load(config)

    maxRTT = settings["nseProperties"]["maxRTT"]
    maxRetries = settings["nseProperties"]["max-retries"]

    outputName = sourceIP + "_to_" + targetRange.replace("/","-")

    if maxRTT == None:
        maxRTT = "5"
    if maxRetries == None:
        maxRetries = "5"

    runNSEs(targetRange, sourceIP, outputName, maxRetries, maxRTT)
    return
