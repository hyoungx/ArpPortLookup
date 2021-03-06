#
# PySNMP MIB module SNMPv2-MIB (http://pysnmp.sf.net)
# ASN.1 source file://MIBS\Cisco\v2\SNMPv2-MIB.my
# Produced by pysmi-0.0.7 at Fri May 26 09:57:45 2017
# On host ? platform ? version ? by user ?
# Using Python version 3.5.1 (v3.5.1:37a07cee5969, Dec  6 2015, 01:38:48) [MSC v.1900 32 bit (Intel)]
#
( ObjectIdentifier, Integer, OctetString, ) = mibBuilder.importSymbols("ASN1", "ObjectIdentifier", "Integer", "OctetString")
( NamedValues, ) = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
( ValueRangeConstraint, ValueSizeConstraint, SingleValueConstraint, ConstraintsIntersection, ConstraintsUnion, ) = mibBuilder.importSymbols("ASN1-REFINEMENT", "ValueRangeConstraint", "ValueSizeConstraint", "SingleValueConstraint", "ConstraintsIntersection", "ConstraintsUnion")
( ModuleCompliance, ObjectGroup, NotificationGroup, ) = mibBuilder.importSymbols("SNMPv2-CONF", "ModuleCompliance", "ObjectGroup", "NotificationGroup")
( Integer32, ObjectIdentity, Unsigned32, MibIdentifier, ModuleIdentity, Counter32, TimeTicks, snmpModules, NotificationType, MibScalar, MibTable, MibTableRow, MibTableColumn, Counter64, mib_2, iso, Bits, IpAddress, Gauge32, ) = mibBuilder.importSymbols("SNMPv2-SMI", "Integer32", "ObjectIdentity", "Unsigned32", "MibIdentifier", "ModuleIdentity", "Counter32", "TimeTicks", "snmpModules", "NotificationType", "MibScalar", "MibTable", "MibTableRow", "MibTableColumn", "Counter64", "mib-2", "iso", "Bits", "IpAddress", "Gauge32")
( TestAndIncr, TextualConvention, TimeStamp, DisplayString, ) = mibBuilder.importSymbols("SNMPv2-TC", "TestAndIncr", "TextualConvention", "TimeStamp", "DisplayString")
snmpMIB = ModuleIdentity((1, 3, 6, 1, 6, 3, 1)).setRevisions(("2002-10-16 00:00", "1995-11-09 00:00", "1993-04-01 00:00",))
snmpMIBObjects = MibIdentifier((1, 3, 6, 1, 6, 3, 1, 1))
system = MibIdentifier((1, 3, 6, 1, 2, 1, 1))
sysDescr = MibScalar((1, 3, 6, 1, 2, 1, 1, 1), DisplayString().subtype(subtypeSpec=ValueSizeConstraint(0,255))).setMaxAccess("readonly")
sysObjectID = MibScalar((1, 3, 6, 1, 2, 1, 1, 2), ObjectIdentifier()).setMaxAccess("readonly")
sysUpTime = MibScalar((1, 3, 6, 1, 2, 1, 1, 3), TimeTicks()).setMaxAccess("readonly")
sysContact = MibScalar((1, 3, 6, 1, 2, 1, 1, 4), DisplayString().subtype(subtypeSpec=ValueSizeConstraint(0,255))).setMaxAccess("readwrite")
sysName = MibScalar((1, 3, 6, 1, 2, 1, 1, 5), DisplayString().subtype(subtypeSpec=ValueSizeConstraint(0,255))).setMaxAccess("readwrite")
sysLocation = MibScalar((1, 3, 6, 1, 2, 1, 1, 6), DisplayString().subtype(subtypeSpec=ValueSizeConstraint(0,255))).setMaxAccess("readwrite")
sysServices = MibScalar((1, 3, 6, 1, 2, 1, 1, 7), Integer32().subtype(subtypeSpec=ValueRangeConstraint(0,127))).setMaxAccess("readonly")
sysORLastChange = MibScalar((1, 3, 6, 1, 2, 1, 1, 8), TimeStamp()).setMaxAccess("readonly")
sysORTable = MibTable((1, 3, 6, 1, 2, 1, 1, 9), )
sysOREntry = MibTableRow((1, 3, 6, 1, 2, 1, 1, 9, 1), ).setIndexNames((0, "SNMPv2-MIB", "sysORIndex"))
sysORIndex = MibTableColumn((1, 3, 6, 1, 2, 1, 1, 9, 1, 1), Integer32().subtype(subtypeSpec=ValueRangeConstraint(1,2147483647)))
sysORID = MibTableColumn((1, 3, 6, 1, 2, 1, 1, 9, 1, 2), ObjectIdentifier()).setMaxAccess("readonly")
sysORDescr = MibTableColumn((1, 3, 6, 1, 2, 1, 1, 9, 1, 3), DisplayString()).setMaxAccess("readonly")
sysORUpTime = MibTableColumn((1, 3, 6, 1, 2, 1, 1, 9, 1, 4), TimeStamp()).setMaxAccess("readonly")
snmp = MibIdentifier((1, 3, 6, 1, 2, 1, 11))
snmpInPkts = MibScalar((1, 3, 6, 1, 2, 1, 11, 1), Counter32()).setMaxAccess("readonly")
snmpInBadVersions = MibScalar((1, 3, 6, 1, 2, 1, 11, 3), Counter32()).setMaxAccess("readonly")
snmpInBadCommunityNames = MibScalar((1, 3, 6, 1, 2, 1, 11, 4), Counter32()).setMaxAccess("readonly")
snmpInBadCommunityUses = MibScalar((1, 3, 6, 1, 2, 1, 11, 5), Counter32()).setMaxAccess("readonly")
snmpInASNParseErrs = MibScalar((1, 3, 6, 1, 2, 1, 11, 6), Counter32()).setMaxAccess("readonly")
snmpEnableAuthenTraps = MibScalar((1, 3, 6, 1, 2, 1, 11, 30), Integer32().subtype(subtypeSpec=ConstraintsUnion(SingleValueConstraint(1, 2,))).clone(namedValues=NamedValues(("enabled", 1), ("disabled", 2),))).setMaxAccess("readwrite")
snmpSilentDrops = MibScalar((1, 3, 6, 1, 2, 1, 11, 31), Counter32()).setMaxAccess("readonly")
snmpProxyDrops = MibScalar((1, 3, 6, 1, 2, 1, 11, 32), Counter32()).setMaxAccess("readonly")
snmpTrap = MibIdentifier((1, 3, 6, 1, 6, 3, 1, 1, 4))
snmpTrapOID = MibScalar((1, 3, 6, 1, 6, 3, 1, 1, 4, 1), ObjectIdentifier()).setMaxAccess("accessiblefornotify")
snmpTrapEnterprise = MibScalar((1, 3, 6, 1, 6, 3, 1, 1, 4, 3), ObjectIdentifier()).setMaxAccess("accessiblefornotify")
snmpTraps = MibIdentifier((1, 3, 6, 1, 6, 3, 1, 1, 5))
coldStart = NotificationType((1, 3, 6, 1, 6, 3, 1, 1, 5, 1)).setObjects(*())
warmStart = NotificationType((1, 3, 6, 1, 6, 3, 1, 1, 5, 2)).setObjects(*())
authenticationFailure = NotificationType((1, 3, 6, 1, 6, 3, 1, 1, 5, 5)).setObjects(*())
snmpSet = MibIdentifier((1, 3, 6, 1, 6, 3, 1, 1, 6))
snmpSetSerialNo = MibScalar((1, 3, 6, 1, 6, 3, 1, 1, 6, 1), TestAndIncr()).setMaxAccess("readwrite")
snmpMIBConformance = MibIdentifier((1, 3, 6, 1, 6, 3, 1, 2))
snmpMIBCompliances = MibIdentifier((1, 3, 6, 1, 6, 3, 1, 2, 1))
snmpMIBGroups = MibIdentifier((1, 3, 6, 1, 6, 3, 1, 2, 2))
snmpBasicCompliance = ModuleCompliance((1, 3, 6, 1, 6, 3, 1, 2, 1, 2)).setObjects(*(("SNMPv2-MIB", "snmpGroup"), ("SNMPv2-MIB", "snmpSetGroup"), ("SNMPv2-MIB", "systemGroup"), ("SNMPv2-MIB", "snmpBasicNotificationsGroup"), ("SNMPv2-MIB", "snmpCommunityGroup1"),))
snmpBasicComplianceRev2 = ModuleCompliance((1, 3, 6, 1, 6, 3, 1, 2, 1, 3)).setObjects(*(("SNMPv2-MIB", "snmpGroup"), ("SNMPv2-MIB", "snmpSetGroup"), ("SNMPv2-MIB", "systemGroup"), ("SNMPv2-MIB", "snmpBasicNotificationsGroup"), ("SNMPv2-MIB", "snmpCommunityGroup1"), ("SNMPv2-MIB", "snmpWarmStartNotificationGroup"),))
snmpGroup = ObjectGroup((1, 3, 6, 1, 6, 3, 1, 2, 2, 8)).setObjects(*(("SNMPv2-MIB", "snmpInPkts"), ("SNMPv2-MIB", "snmpInBadVersions"), ("SNMPv2-MIB", "snmpInASNParseErrs"), ("SNMPv2-MIB", "snmpSilentDrops"), ("SNMPv2-MIB", "snmpProxyDrops"), ("SNMPv2-MIB", "snmpEnableAuthenTraps"),))
snmpCommunityGroup1 = ObjectGroup((1, 3, 6, 1, 6, 3, 1, 2, 2, 9)).setObjects(*(("SNMPv2-MIB", "snmpInBadCommunityNames"), ("SNMPv2-MIB", "snmpInBadCommunityUses"),))
snmpSetGroup = ObjectGroup((1, 3, 6, 1, 6, 3, 1, 2, 2, 5)).setObjects(*(("SNMPv2-MIB", "snmpSetSerialNo"),))
systemGroup = ObjectGroup((1, 3, 6, 1, 6, 3, 1, 2, 2, 6)).setObjects(*(("SNMPv2-MIB", "sysDescr"), ("SNMPv2-MIB", "sysObjectID"), ("SNMPv2-MIB", "sysUpTime"), ("SNMPv2-MIB", "sysContact"), ("SNMPv2-MIB", "sysName"), ("SNMPv2-MIB", "sysLocation"), ("SNMPv2-MIB", "sysServices"), ("SNMPv2-MIB", "sysORLastChange"), ("SNMPv2-MIB", "sysORID"), ("SNMPv2-MIB", "sysORUpTime"), ("SNMPv2-MIB", "sysORDescr"),))
snmpBasicNotificationsGroup = NotificationGroup((1, 3, 6, 1, 6, 3, 1, 2, 2, 7)).setObjects(*(("SNMPv2-MIB", "coldStart"), ("SNMPv2-MIB", "authenticationFailure"),))
snmpWarmStartNotificationGroup = NotificationGroup((1, 3, 6, 1, 6, 3, 1, 2, 2, 11)).setObjects(*(("SNMPv2-MIB", "warmStart"),))
snmpNotificationGroup = ObjectGroup((1, 3, 6, 1, 6, 3, 1, 2, 2, 12)).setObjects(*(("SNMPv2-MIB", "snmpTrapOID"), ("SNMPv2-MIB", "snmpTrapEnterprise"),))
snmpOutPkts = MibScalar((1, 3, 6, 1, 2, 1, 11, 2), Counter32()).setMaxAccess("readonly")
snmpInTooBigs = MibScalar((1, 3, 6, 1, 2, 1, 11, 8), Counter32()).setMaxAccess("readonly")
snmpInNoSuchNames = MibScalar((1, 3, 6, 1, 2, 1, 11, 9), Counter32()).setMaxAccess("readonly")
snmpInBadValues = MibScalar((1, 3, 6, 1, 2, 1, 11, 10), Counter32()).setMaxAccess("readonly")
snmpInReadOnlys = MibScalar((1, 3, 6, 1, 2, 1, 11, 11), Counter32()).setMaxAccess("readonly")
snmpInGenErrs = MibScalar((1, 3, 6, 1, 2, 1, 11, 12), Counter32()).setMaxAccess("readonly")
snmpInTotalReqVars = MibScalar((1, 3, 6, 1, 2, 1, 11, 13), Counter32()).setMaxAccess("readonly")
snmpInTotalSetVars = MibScalar((1, 3, 6, 1, 2, 1, 11, 14), Counter32()).setMaxAccess("readonly")
snmpInGetRequests = MibScalar((1, 3, 6, 1, 2, 1, 11, 15), Counter32()).setMaxAccess("readonly")
snmpInGetNexts = MibScalar((1, 3, 6, 1, 2, 1, 11, 16), Counter32()).setMaxAccess("readonly")
snmpInSetRequests = MibScalar((1, 3, 6, 1, 2, 1, 11, 17), Counter32()).setMaxAccess("readonly")
snmpInGetResponses = MibScalar((1, 3, 6, 1, 2, 1, 11, 18), Counter32()).setMaxAccess("readonly")
snmpInTraps = MibScalar((1, 3, 6, 1, 2, 1, 11, 19), Counter32()).setMaxAccess("readonly")
snmpOutTooBigs = MibScalar((1, 3, 6, 1, 2, 1, 11, 20), Counter32()).setMaxAccess("readonly")
snmpOutNoSuchNames = MibScalar((1, 3, 6, 1, 2, 1, 11, 21), Counter32()).setMaxAccess("readonly")
snmpOutBadValues = MibScalar((1, 3, 6, 1, 2, 1, 11, 22), Counter32()).setMaxAccess("readonly")
snmpOutGenErrs = MibScalar((1, 3, 6, 1, 2, 1, 11, 24), Counter32()).setMaxAccess("readonly")
snmpOutGetRequests = MibScalar((1, 3, 6, 1, 2, 1, 11, 25), Counter32()).setMaxAccess("readonly")
snmpOutGetNexts = MibScalar((1, 3, 6, 1, 2, 1, 11, 26), Counter32()).setMaxAccess("readonly")
snmpOutSetRequests = MibScalar((1, 3, 6, 1, 2, 1, 11, 27), Counter32()).setMaxAccess("readonly")
snmpOutGetResponses = MibScalar((1, 3, 6, 1, 2, 1, 11, 28), Counter32()).setMaxAccess("readonly")
snmpOutTraps = MibScalar((1, 3, 6, 1, 2, 1, 11, 29), Counter32()).setMaxAccess("readonly")
snmpObsoleteGroup = ObjectGroup((1, 3, 6, 1, 6, 3, 1, 2, 2, 10)).setObjects(*(("SNMPv2-MIB", "snmpOutPkts"), ("SNMPv2-MIB", "snmpInTooBigs"), ("SNMPv2-MIB", "snmpInNoSuchNames"), ("SNMPv2-MIB", "snmpInBadValues"), ("SNMPv2-MIB", "snmpInReadOnlys"), ("SNMPv2-MIB", "snmpInGenErrs"), ("SNMPv2-MIB", "snmpInTotalReqVars"), ("SNMPv2-MIB", "snmpInTotalSetVars"), ("SNMPv2-MIB", "snmpInGetRequests"), ("SNMPv2-MIB", "snmpInGetNexts"), ("SNMPv2-MIB", "snmpInSetRequests"), ("SNMPv2-MIB", "snmpInGetResponses"), ("SNMPv2-MIB", "snmpInTraps"), ("SNMPv2-MIB", "snmpOutTooBigs"), ("SNMPv2-MIB", "snmpOutNoSuchNames"), ("SNMPv2-MIB", "snmpOutBadValues"), ("SNMPv2-MIB", "snmpOutGenErrs"), ("SNMPv2-MIB", "snmpOutGetRequests"), ("SNMPv2-MIB", "snmpOutGetNexts"), ("SNMPv2-MIB", "snmpOutSetRequests"), ("SNMPv2-MIB", "snmpOutGetResponses"), ("SNMPv2-MIB", "snmpOutTraps"),))
mibBuilder.exportSymbols("SNMPv2-MIB", snmpInBadVersions=snmpInBadVersions, snmpInTotalReqVars=snmpInTotalReqVars, snmpWarmStartNotificationGroup=snmpWarmStartNotificationGroup, snmpSetSerialNo=snmpSetSerialNo, snmpInSetRequests=snmpInSetRequests, snmpOutGenErrs=snmpOutGenErrs, PYSNMP_MODULE_ID=snmpMIB, snmpInBadCommunityNames=snmpInBadCommunityNames, snmpEnableAuthenTraps=snmpEnableAuthenTraps, snmpNotificationGroup=snmpNotificationGroup, snmpInGetResponses=snmpInGetResponses, snmpMIBCompliances=snmpMIBCompliances, snmpInASNParseErrs=snmpInASNParseErrs, snmpInGetNexts=snmpInGetNexts, snmpOutNoSuchNames=snmpOutNoSuchNames, snmpOutSetRequests=snmpOutSetRequests, snmpMIBConformance=snmpMIBConformance, sysOREntry=sysOREntry, system=system, snmpBasicCompliance=snmpBasicCompliance, sysORDescr=sysORDescr, coldStart=coldStart, snmpInPkts=snmpInPkts, snmpInBadValues=snmpInBadValues, snmpInReadOnlys=snmpInReadOnlys, snmpObsoleteGroup=snmpObsoleteGroup, snmpInTooBigs=snmpInTooBigs, sysORID=sysORID, snmpTrap=snmpTrap, snmpInGenErrs=snmpInGenErrs, snmpMIB=snmpMIB, snmpOutTooBigs=snmpOutTooBigs, snmpTraps=snmpTraps, snmpSetGroup=snmpSetGroup, sysUpTime=sysUpTime, sysServices=sysServices, snmp=snmp, snmpOutGetResponses=snmpOutGetResponses, snmpSilentDrops=snmpSilentDrops, sysORLastChange=sysORLastChange, sysORTable=sysORTable, snmpOutTraps=snmpOutTraps, snmpProxyDrops=snmpProxyDrops, snmpOutGetRequests=snmpOutGetRequests, sysLocation=sysLocation, snmpInGetRequests=snmpInGetRequests, authenticationFailure=authenticationFailure, systemGroup=systemGroup, snmpSet=snmpSet, snmpBasicNotificationsGroup=snmpBasicNotificationsGroup, snmpTrapEnterprise=snmpTrapEnterprise, sysORIndex=sysORIndex, snmpInNoSuchNames=snmpInNoSuchNames, snmpMIBObjects=snmpMIBObjects, sysDescr=sysDescr, snmpMIBGroups=snmpMIBGroups, sysContact=sysContact, snmpInBadCommunityUses=snmpInBadCommunityUses, snmpBasicComplianceRev2=snmpBasicComplianceRev2, snmpGroup=snmpGroup, snmpTrapOID=snmpTrapOID, sysName=sysName, sysORUpTime=sysORUpTime, warmStart=warmStart, snmpInTotalSetVars=snmpInTotalSetVars, snmpOutBadValues=snmpOutBadValues, snmpCommunityGroup1=snmpCommunityGroup1, snmpOutGetNexts=snmpOutGetNexts, sysObjectID=sysObjectID, snmpInTraps=snmpInTraps, snmpOutPkts=snmpOutPkts)
