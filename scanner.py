import json
from bluekeep import exploitBluekeep
from eternalblue import exploitEternalblue
from smbghost import exploitSmbghost

fileName = input("Enter file name: ")

jsonData = json.load(open(fileName, 'r'))

resBlueKeep = []
resEternalBlue = []
resSmbghost = []

for item in jsonData:
    for port in item["ports"]:
        hostname = "eltons-dev"
        username = "elton"
        if exploitEternalblue(item["ip"], port):
            resEternalBlue.append({
                "ip": item["ip"],
                "port": port
            })
        if exploitBluekeep(item["ip"], port):
            resBlueKeep.append({
                "ip": item["ip"],
                "port": port
            })
        if exploitSmbghost(item["ip"]):
            resSmbghost.append({
                "ip": item["ip"],
                "port": port
            })

resBlueKeepJson = json.dumps(resBlueKeep)
jsonFileNameBluekeep = fileName.split(".")[0] + "BlueKeep.json"
open(jsonFileNameBluekeep, "w").write(resBlueKeepJson)
print(str(len(resBlueKeep)) + " items has bluekeep vulnerability, added to file " + jsonFileNameBluekeep)

resEternalblueJson = json.dumps(resEternalBlue)
jsonFileNameEternalBlue = fileName.split(".")[0] + "Eternalblue.json"
open(jsonFileNameEternalBlue, "w").write(resEternalblueJson)
print(str(len(resEternalBlue)) + " items has eternalblue vulnerability, added to file " + jsonFileNameEternalBlue)

resSmbghostJson = json.dumps(resSmbghost)
jsonFileNameEternalBlue = fileName.split(".")[0] + "Smbghost.json"
open(jsonFileNameEternalBlue, "w").write(resSmbghostJson)
print(str(len(resSmbghostJson)) + " items has smbghost vulnerability, added to file " + jsonFileNameEternalBlue)
