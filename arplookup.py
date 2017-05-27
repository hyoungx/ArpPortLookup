#!/usr/local/bin/python3.6

from pysnmp.hlapi import *
import sqlite3
import os
import sys
import timeit
import argparse

startTime = timeit.default_timer()



ipNetToMediaTable = '.1.3.6.1.2.1.4.22'+'.1'
dot1dTpFdbAddress = '.1.3.6.1.2.1.17.4.3' + '.1'
vtpVlanTable = '.1.3.6.1.4.1.9.9.46.1.3.1'+'.1'
ifTable = '.1.3.6.1.2.1.2.2'+'.1'
dot1dBasePortTable = '.1.3.6.1.2.1.17.1.4'+'.1'
COMMUNITY = 'public'
defaultNonRepeaters = 0
defaultMaxRepetitions = 10
UdpPortNumber = 161
devicedatabase = 'device.db'
TABLES = 'tables.db'
refreshTables = False
verbose = True
usecache = True
compiledMibDirectory = os.path.join('.','CompiledMIBS')

try:
    ipaddress = sys.argv[1]
except IndexError:
    pass

connDevice = sqlite3.connect(os.path.join(os.path.dirname(os.path.abspath(__file__)),devicedatabase))
curDevice = connDevice.cursor()
try:
    curDevice.execute('ALTER TABLE device ADD COLUMN cached text')
except sqlite3.OperationalError:
    pass

curDevice.execute('SELECT COUNT(IP) FROM device')
deviceCount = curDevice.fetchone()[0]
i = 0
curDevice.execute('SELECT IP FROM device where position = "backbone"')
backbones = curDevice.fetchall()
curDevice.execute('SELECT IP FROM device')
devices = []
for cD in curDevice.fetchall():
    devices.append(cD[0])

class NotSupportedVendor(Exception):
    def __init__(self, vendor=None):
        if vendor is None:
            self.msg = 'Not Supported Vendor.'
        else:
            self.msg = ' '.join(['Not Supported Vendor. Add', vendor,"'s OID"])
    def __str__(self):
        return self.msg

class NotSupportedTable(Exception):
    def __init__(self, table=None):
        if table is None:
            self.msg = 'Not Supported Table.'
        else:
            self.msg = ' '.join(['Not Supported Table. Add', str(table),"'s OID"])
    def __str__(self):
        return self.msg

def getIndexValue(ipAddress, tableOID, community, udpPortNumber):
    indexValue = ''
    g = nextCmd(SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ipAddress, udpPortNumber)),
                ContextData(),
                ObjectType(ObjectIdentity(tableOID)))
    errorIndication, errorStatus, errorIndex, varBinds = next(g)
    if errorIndication is not None:
        return indexValue, errorIndication
    firstItemOid = '.'.join(['',str(varBinds[0][0].getOid())])
    if firstItemOid[:len(tableOID)] != tableOID:
        errorIndication = 'Table is empty'
        return indexValue, errorIndication
    firstAccessibleColumnIndex = firstItemOid[len(tableOID)+1:].split('.')[0]

    g = bulkCmd(SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ipAddress, udpPortNumber)),
                ContextData(),
                defaultNonRepeaters, defaultMaxRepetitions,
                ObjectType(ObjectIdentity(tableOID)))
    while (True):
        errorIndication, errorStatus, errorIndex, varBinds = next(g)
        if errorIndication is not None:
            return indexValue, errorIndication
        objectIdentity = '.'.join(['',str(varBinds[0][0].getOid())])
        if objectIdentity[:len(tableOID)+2] != '.'.join([tableOID,firstAccessibleColumnIndex]):
            return indexValue, errorIndication
        indexValue = objectIdentity[len(tableOID) + 3:]
        yield indexValue, errorIndication

def getTable(ipAddress, tableOID, community, udpPortNumber):
    value = ''
    g = bulkCmd(SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ipAddress, udpPortNumber)),
                ContextData(),
                defaultNonRepeaters, defaultMaxRepetitions,
                ObjectType(ObjectIdentity(tableOID)))
    while (True):
        errorIndication, errorStatus, errorIndex, varBinds = next(g)
        if errorIndication is not None:
            return value, errorIndication
        objectIdentity = '.'.join(['', str(varBinds[0][0].getOid())])
        if objectIdentity[:len(tableOID)] != tableOID:
            return value, errorIndication
        value = varBinds[0][1].prettyPrint()
        print(value)
        yield value, errorIndication

def getTableColumn(ipAddress, tableOID, column, community, udpPortNumber):
    value = ''
    g = bulkCmd(SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ipAddress, udpPortNumber)),
                ContextData(),
                defaultNonRepeaters, defaultMaxRepetitions,
                ObjectType(ObjectIdentity(tableOID+'.'+str(column))))
    while (True):
        errorIndication, errorStatus, errorIndex, varBinds = next(g)
        if errorIndication is not None:
            return value, errorIndication
        objectIdentity = '.'.join(['', str(varBinds[0][0].getOid())])
        if objectIdentity[:len(tableOID)+len(str(column))+1] != '.'.join([tableOID,str(column)]):
            return value, errorIndication
        value = varBinds[0][1].prettyPrint()
        yield value, errorIndication

def getTableRow(ipAddress, tableOID, columns, community, udpPortNumber):
    values = []
    f = {}
    for c in columns:
        f[c] = bulkCmd(SnmpEngine(),
                       CommunityData(community),
                       UdpTransportTarget((ipAddress, udpPortNumber)),
                       ContextData(),
                       defaultNonRepeaters, defaultMaxRepetitions,
                       ObjectType(ObjectIdentity('.'.join([tableOID, str(c)]))))
    while(True):
        values.clear()
        for c in columns:
            errorIndication, errorStatus, errorIndex, varBinds = next(f[c])
            if errorIndication is not None:
                return values, errorIndication
            objectIdentity = '.'.join(['', str(varBinds[0][0].getOid())])
            if objectIdentity[:len(tableOID)+len(str(c))+1] != '.'.join([tableOID,str(c)]):
                return values, errorIndication
            values.append(varBinds[0][1].prettyPrint())
        yield values, errorIndication

def printError(error):
    print('An error [' + str(error) + '] is occurred on the switch [ ' + d + ' ]')

def macPrettyPrint(mac):
    results = []
    if len(mac) != 14 or mac[:2] != '0x':
        return "check format"
    for i in range(1,7):
        results.append(mac[i+1:i+3])
    return ':'.join(results).upper()

def searchARP(ipaddress):
    results = []
    sql = ''.join(['''select matched.MAC, matched.ifDescr, matched.Device
            from (
                select distinct *
                from (
                    select distinct arpPortIndex.IP, arpPortIndex.MAC, arpPortIndex.Device, arpPortIndex.portIndex, dot1dBasePortTable.ifIndex
                    from (
                        select DISTINCT ipNetToMediaTable.IP, ipNetToMediaTable.MAC, dot1dTpFdbAddress.Device, dot1dTpFdbAddress.portIndex
                        from ipNetToMediaTable
                        inner join dot1dTpFdbAddress on ipNetToMediaTable.MAC=dot1dTpFdbAddress.MAC
                        where ipNetToMediaTable.IP = :ipaddress
                    ) as arpPortIndex
                    inner join dot1dBasePortTable on arpPortIndex.portIndex=dot1dBasePortTable.portIndex and arpPortIndex.Device=dot1dBasePortTable.Device 
                ) as arpIfIndex
                inner join ifTable on arpIfIndex.ifIndex=ifTable.ifIndex and arpIfIndex.Device=ifTable.Device
            ) as matched,
            (
                select ifIndexTable.Device, ifIndexTable.portIndex
                from (
                    select distinct portIndexTable.Device, portIndexTable.portIndex, dot1dBasePortTable.ifIndex
                    from (
                        select distinct dot1dTpFdbAddress.Device, dot1dTpFdbAddress.portIndex
                        from dot1dTpFdbAddress
                        where dot1dTpFdbAddress.MAC in (
                            select distinct ifTable.ifPhysAddress
                            from ifTable
                            where ifTable.Device in ("''','","'.join(b[0] for b in backbones),'''")
                        ) 
                    ) as portIndexTable
                    inner join dot1dBasePortTable on portIndexTable.portIndex=dot1dBasePortTable.portIndex and portIndexTable.Device=dot1dBasePortTable.Device
                ) as ifIndexTable
                inner join ifTable on ifIndexTable.ifIndex=ifTable.ifIndex and ifIndexTable.Device=ifTable.Device
            ) as uplinks
            where matched.Device=uplinks.Device and matched.portIndex!=uplinks.portIndex
    '''])
    cur.execute(sql,{"ipaddress": ipaddress})
    macAddresses = cur.fetchall()
    for mAdd in macAddresses:
        # cur.execute('SELECT ')
        g = getCmd(SnmpEngine(),
                   CommunityData(COMMUNITY),
                   UdpTransportTarget((mAdd[2], UdpPortNumber)),
                   ContextData(),
                   ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0)))
        curDevice.execute('SELECT hostname, cached FROM device WHERE IP = :ipaddress', {"ipaddress": mAdd[2]})
        cachedDevice = curDevice.fetchone()
        if len(cachedDevice) == 0 or cachedDevice[1] != 'cached':
            errorIndication, errorStatus, errorIndex, varBinds = next(g)
            hostname = str(varBinds[0].__getitem__(1))
            curDevice.execute('UPDATE device SET hostname=:hostname, cached=:cached WHERE IP=:ipaddress',
                              {"hostname": hostname, "ipaddress": mAdd[2], "cached": 'cached'})
            connDevice.commit()
        else:
            hostname = cachedDevice[0]
        _ = list(mAdd)
        _.append(hostname)
        results.append(_)
    return results

def printResult(results):
    print('=' * 110)
    print(''.join(['IP Address'.ljust(20), 'Mac Address'.ljust(20), 'NW Hostname'.ljust(25), 'NW Interface'.ljust(25),
                   'NW IP address'.ljust(20)]))
    print('-' * 110)
    for r in results:
        print(''.join(
            [ipaddress[:19].ljust(20), macPrettyPrint(r[0])[:19].ljust(20), r[3][:24].ljust(25), r[1][:24].ljust(25),
             r[2][:19].ljust(20)]))
        print('-' * 110)
    print(''.join(['IP Address'.ljust(20), 'Mac Address'.ljust(20), 'NW Hostname'.ljust(25), 'NW Interface'.ljust(25),
                   'NW IP address'.ljust(20)]))
    print('=' * 110)

def getVlans(ipaddress, vendor, community, udpPortNumber):
    if vendor.lower() == "cisco":
        vlanTableOid = vtpVlanTable
    else:
        raise NotSupportedVendor(vendor)
    vlans = []
    g = getIndexValue(ipaddress, vlanTableOid, community, udpPortNumber)
    try:
        while (True):
            indexValue, errorIndication = next(g)
            if errorIndication is not None:
                printError(errorIndication)
            vlans.append(indexValue[2:])
    except StopIteration:
        pass
    return vlans

def rebuildTables(devices, tables):
    if not isinstance(devices, (tuple,list)):
        devices = (devices,)
    if not isinstance(tables, (tuple,list)):
        tables = (tables,)
    for t in tables:
        if t == "ipNetToMediaTable":
            for d in devices:
                cur.execute('''DELETE FROM ipNetToMediaTable WHERE Device = :device''', {"device": d})
                g = getTableRow(d, ipNetToMediaTable, (2, 3, 1), COMMUNITY, UdpPortNumber)
                try:
                    while(True):
                        arpEntry, errorIndication = next(g)
                        if errorIndication is not None:
                            printError(errorIndication)
                        arpEntry.append(d)
                        cur.execute('INSERT INTO ipNetToMediaTable(MAC, IP, ipNetToMediaIfIndex, Device) VALUES (?, ?, ?, ?)', arpEntry)
                except StopIteration:
                    pass
            conn.commit()
        elif t == "ifTable":
            for d in devices:
                cur.execute('DELETE FROM ifTable WHERE Device = :device', {"device": d})
                g = getTableRow(d, ifTable, (1, 2, 6), COMMUNITY, UdpPortNumber)
                try:
                    while (True):
                        ifIndexEntry, errorIndication = next(g)
                        if errorIndication is not None:
                            printError(errorIndication)
                        ifIndexEntry.append(d)
                        cur.execute('INSERT INTO ifTable(ifIndex, ifDescr, ifPhysAddress, Device) VALUES (?, ?, ?, ?)', ifIndexEntry)
                except StopIteration:
                    pass
            conn.commit()
        elif t == "dot1dTpFdbAddress":
            for d in devices:
                vlans = getVlans(d, 'cisco', COMMUNITY, UdpPortNumber)
                for v in vlans:
                    g = getTableRow(d, dot1dTpFdbAddress, (1,2), '@'.join([COMMUNITY, str(v)]), UdpPortNumber)
                    try:
                        while(True):
                            macEntry, errorIndication = next(g)
                            if errorIndication is not None:
                                printError(errorIndication)
                            macEntry.append(d)
                            cur.execute('INSERT INTO dot1dTpFdbAddress(MAC, portIndex, Device) VALUES (?, ?, ?)', macEntry)
                    except StopIteration:
                        pass
            conn.commit()
        elif t == "dot1dBasePortTable":
            for d in devices:
                vlans = getVlans(d, 'cisco', COMMUNITY, UdpPortNumber)
                for v in vlans:
                    if v == 1:
                        continue
                    g = getTableRow(d, dot1dBasePortTable, (1,2), '@'.join([COMMUNITY,str(v)]), UdpPortNumber)
                    try:
                        while(True):
                            portIndexEntry, errorIndication = next(g)
                            if errorIndication is not None:
                                printError(errorIndication)
                            portIndexEntry.append(d)
                            cur.execute('INSERT INTO dot1dBasePortTable(portIndex, ifIndex, Device) VALUES (?, ?, ?)', portIndexEntry)
                    except StopIteration:
                        pass
            conn.commit()
        else:
            raise NotSupportedTable(t)

scriptPath = os.path.dirname(os.path.abspath(__file__))
tablePath = os.path.join(scriptPath,'tables.db')
tableBakPath = os.path.join(scriptPath,'tables.db.bak')

print(tablePath)

if not os.path.exists(tablePath):
    print('tables.db not found. Building tables.db. ')
    refreshTables = True
    usecache = False
    existTables = False
else:
    refreshTables = False
    usecache = True
    existTables = True

if refreshTables:
    if os.path.exists(tablePath):
        if os.path.exists(tableBakPath):
            os.remove(tableBakPath)
        os.rename(tablePath, tableBakPath)

conn = sqlite3.connect(tablePath)
cur = conn.cursor()

cur.execute('''CREATE TABLE IF NOT EXISTS ipNetToMediaTable
                (IP text, MAC text, Device text, ipNetToMediaIfIndex int)''')
cur.execute('''CREATE TABLE IF NOT EXISTS ifTable
                (ifIndex int, ifDescr text, Device text, ifPhysAddress text)''')
cur.execute('''CREATE TABLE IF NOT EXISTS dot1dTpFdbAddress
                (MAC text, portIndex int, Device text)''')
cur.execute('''CREATE TABLE IF NOT EXISTS dot1dBasePortTable
                (portIndex int, ifIndex int, Device text)''')

# cur.execute('''ALTER TABLE ipNetToMediaTable ADD COLUMN ipNetToMediaIfIndex int''')



# cur.execute('SELECT * FROM ipNetToMediaTable WHERE ip = :ipaddress', {"ipaddress": ipaddress})
# cacheResult = cur.fetchall()
if usecache:
    results = searchARP(ipaddress)
    if len(results) != 0:
        printResult(results)
    else:
        print(' '.join([ipaddress,'is not cached.']))
        usecache = False

    # if True:
while not usecache:
    if existTables:
        print('SNMP queries will be placed to Backbones.')
        print('It takes about several minutes.')
        for b in backbones:
            i += 1
            print(''.join(['gethering snmp information from ', b[0], ' (', str(i), ' of ', str(len(backbones)), ')']))
            try:
                rebuildTables(b[0], ("ipNetToMediaTable", "dot1dTpFdbAddress", "dot1dBasePortTable", "ifTable"))
            except NotSupportedVendor as e:
                print(e)
                exit()
            except NotSupportedTable as e:
                print(e)
                exit()
        results = searchARP(ipaddress)
        if len(results) == 0:
            print(" ".join(["Can't find the IP address", ipaddress]))
            break
        cur.execute('select Device, ipNetToMediaIfIndex from ipNetToMediaTable where IP = :ipaddress',
                    {'ipaddress': ipaddress})
        ifIndices = cur.fetchall()
        deviceMatched = []
        for ii in ifIndices:
            cur.execute('select IP from ipNetToMediaTable where Device = :device and ipNetToMediaIfIndex = :ipNetToMediaIfIndex ',
                        {"device": ii[0], "ipNetToMediaIfIndex": ii[1]})
            ipMatched = cur.fetchall()
            for iM in ipMatched:
                curDevice.execute('select IP from device where IP = :ip', {"ip": iM[0]})
                matched = curDevice.fetchall()
                for md in matched:
                    deviceMatched.append(md[0])
        devices = set(deviceMatched)
        for d in devices:
            i = i + 1
            print(''.join(['gethering snmp information from ', d, ' (', str(i), ' of ', str(targetDeviceCount), ')']))
            try:
                rebuildTables(d, ("ipNetToMediaTable", "dot1dTpFdbAddress", "dot1dBasePortTable", "ifTable"))
            except NotSupportedVendor as e:
                print(e)
                exit()
            except NotSupportedTable as e:
                print(e)
                exit()

        results = searchARP(ipaddress)
        printResult(results)
        break
    else:
        print("rebuilding database for every devices.")
        print('It takes VERY long time.(about an hour)')
        for d in devices:
            i += 1
            print(
                ''.join(['gethering snmp information from ', d, ' (', str(i), ' of ', str(deviceCount), ')']))
            try:
                rebuildTables(d, ("ipNetToMediaTable", "dot1dTpFdbAddress", "dot1dBasePortTable", "ifTable"))
            except NotSupportedVendor as e:
                print(e)
                exit()
            except NotSupportedTable as e:
                print(e)
                exit()
        results = searchARP(ipaddress)
        printResult(results)
        break

endTime = timeit.default_timer()

if verbose:
    print('execution time is ' + str(round(endTime-startTime,3)) + 'seconds.')
