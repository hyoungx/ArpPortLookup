#
# PySNMP MIB module IF-MIB (http://pysnmp.sf.net)
# ASN.1 source file://MIBS\Cisco\v2\IF-MIB.my
# Produced by pysmi-0.0.7 at Fri May 26 09:57:45 2017
# On host ? platform ? version ? by user ?
# Using Python version 3.5.1 (v3.5.1:37a07cee5969, Dec  6 2015, 01:38:48) [MSC v.1900 32 bit (Intel)]
#
( ObjectIdentifier, Integer, OctetString, ) = mibBuilder.importSymbols("ASN1", "ObjectIdentifier", "Integer", "OctetString")
( NamedValues, ) = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
( ValueRangeConstraint, ValueSizeConstraint, SingleValueConstraint, ConstraintsIntersection, ConstraintsUnion, ) = mibBuilder.importSymbols("ASN1-REFINEMENT", "ValueRangeConstraint", "ValueSizeConstraint", "SingleValueConstraint", "ConstraintsIntersection", "ConstraintsUnion")
( IANAifType, ) = mibBuilder.importSymbols("IANAifType-MIB", "IANAifType")
( ModuleCompliance, ObjectGroup, NotificationGroup, ) = mibBuilder.importSymbols("SNMPv2-CONF", "ModuleCompliance", "ObjectGroup", "NotificationGroup")
( snmpTraps, ) = mibBuilder.importSymbols("SNMPv2-MIB", "snmpTraps")
( Integer32, ObjectIdentity, Unsigned32, MibIdentifier, ModuleIdentity, Counter32, TimeTicks, Counter64, NotificationType, MibScalar, MibTable, MibTableRow, MibTableColumn, mib_2, iso, Bits, IpAddress, Gauge32, ) = mibBuilder.importSymbols("SNMPv2-SMI", "Integer32", "ObjectIdentity", "Unsigned32", "MibIdentifier", "ModuleIdentity", "Counter32", "TimeTicks", "Counter64", "NotificationType", "MibScalar", "MibTable", "MibTableRow", "MibTableColumn", "mib-2", "iso", "Bits", "IpAddress", "Gauge32")
( TimeStamp, TextualConvention, TruthValue, AutonomousType, PhysAddress, RowStatus, DisplayString, TestAndIncr, ) = mibBuilder.importSymbols("SNMPv2-TC", "TimeStamp", "TextualConvention", "TruthValue", "AutonomousType", "PhysAddress", "RowStatus", "DisplayString", "TestAndIncr")
ifMIB = ModuleIdentity((1, 3, 6, 1, 2, 1, 31)).setRevisions(("2000-06-14 00:00", "1996-02-28 21:55", "1993-11-08 21:55",))
ifMIBObjects = MibIdentifier((1, 3, 6, 1, 2, 1, 31, 1))
interfaces = MibIdentifier((1, 3, 6, 1, 2, 1, 2))
class OwnerString(OctetString, TextualConvention):
    displayHint = '255a'
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(0,255)

class InterfaceIndex(Integer32, TextualConvention):
    displayHint = 'd'
    subtypeSpec = Integer32.subtypeSpec+ValueRangeConstraint(1,2147483647)

class InterfaceIndexOrZero(Integer32, TextualConvention):
    displayHint = 'd'
    subtypeSpec = Integer32.subtypeSpec+ValueRangeConstraint(0,2147483647)

ifNumber = MibScalar((1, 3, 6, 1, 2, 1, 2, 1), Integer32()).setMaxAccess("readonly")
ifTableLastChange = MibScalar((1, 3, 6, 1, 2, 1, 31, 1, 5), TimeTicks()).setMaxAccess("readonly")
ifTable = MibTable((1, 3, 6, 1, 2, 1, 2, 2), )
ifEntry = MibTableRow((1, 3, 6, 1, 2, 1, 2, 2, 1), ).setIndexNames((0, "IF-MIB", "ifIndex"))
ifIndex = MibTableColumn((1, 3, 6, 1, 2, 1, 2, 2, 1, 1), InterfaceIndex()).setMaxAccess("readonly")
ifDescr = MibTableColumn((1, 3, 6, 1, 2, 1, 2, 2, 1, 2), DisplayString().subtype(subtypeSpec=ValueSizeConstraint(0,255))).setMaxAccess("readonly")
ifType = MibTableColumn((1, 3, 6, 1, 2, 1, 2, 2, 1, 3), IANAifType()).setMaxAccess("readonly")
ifMtu = MibTableColumn((1, 3, 6, 1, 2, 1, 2, 2, 1, 4), Integer32()).setMaxAccess("readonly")
ifSpeed = MibTableColumn((1, 3, 6, 1, 2, 1, 2, 2, 1, 5), Gauge32()).setMaxAccess("readonly")
ifPhysAddress = MibTableColumn((1, 3, 6, 1, 2, 1, 2, 2, 1, 6), PhysAddress()).setMaxAccess("readonly")
ifAdminStatus = MibTableColumn((1, 3, 6, 1, 2, 1, 2, 2, 1, 7), Integer32().subtype(subtypeSpec=ConstraintsUnion(SingleValueConstraint(1, 2, 3,))).clone(namedValues=NamedValues(("up", 1), ("down", 2), ("testing", 3),))).setMaxAccess("readwrite")
ifOperStatus = MibTableColumn((1, 3, 6, 1, 2, 1, 2, 2, 1, 8), Integer32().subtype(subtypeSpec=ConstraintsUnion(SingleValueConstraint(1, 2, 3, 4, 5, 6, 7,))).clone(namedValues=NamedValues(("up", 1), ("down", 2), ("testing", 3), ("unknown", 4), ("dormant", 5), ("notPresent", 6), ("lowerLayerDown", 7),))).setMaxAccess("readonly")
ifLastChange = MibTableColumn((1, 3, 6, 1, 2, 1, 2, 2, 1, 9), TimeTicks()).setMaxAccess("readonly")
ifInOctets = MibTableColumn((1, 3, 6, 1, 2, 1, 2, 2, 1, 10), Counter32()).setMaxAccess("readonly")
ifInUcastPkts = MibTableColumn((1, 3, 6, 1, 2, 1, 2, 2, 1, 11), Counter32()).setMaxAccess("readonly")
ifInNUcastPkts = MibTableColumn((1, 3, 6, 1, 2, 1, 2, 2, 1, 12), Counter32()).setMaxAccess("readonly")
ifInDiscards = MibTableColumn((1, 3, 6, 1, 2, 1, 2, 2, 1, 13), Counter32()).setMaxAccess("readonly")
ifInErrors = MibTableColumn((1, 3, 6, 1, 2, 1, 2, 2, 1, 14), Counter32()).setMaxAccess("readonly")
ifInUnknownProtos = MibTableColumn((1, 3, 6, 1, 2, 1, 2, 2, 1, 15), Counter32()).setMaxAccess("readonly")
ifOutOctets = MibTableColumn((1, 3, 6, 1, 2, 1, 2, 2, 1, 16), Counter32()).setMaxAccess("readonly")
ifOutUcastPkts = MibTableColumn((1, 3, 6, 1, 2, 1, 2, 2, 1, 17), Counter32()).setMaxAccess("readonly")
ifOutNUcastPkts = MibTableColumn((1, 3, 6, 1, 2, 1, 2, 2, 1, 18), Counter32()).setMaxAccess("readonly")
ifOutDiscards = MibTableColumn((1, 3, 6, 1, 2, 1, 2, 2, 1, 19), Counter32()).setMaxAccess("readonly")
ifOutErrors = MibTableColumn((1, 3, 6, 1, 2, 1, 2, 2, 1, 20), Counter32()).setMaxAccess("readonly")
ifOutQLen = MibTableColumn((1, 3, 6, 1, 2, 1, 2, 2, 1, 21), Gauge32()).setMaxAccess("readonly")
ifSpecific = MibTableColumn((1, 3, 6, 1, 2, 1, 2, 2, 1, 22), ObjectIdentifier()).setMaxAccess("readonly")
ifXTable = MibTable((1, 3, 6, 1, 2, 1, 31, 1, 1), )
ifXEntry = MibTableRow((1, 3, 6, 1, 2, 1, 31, 1, 1, 1), )
ifEntry.registerAugmentions(("IF-MIB", "ifXEntry"))
ifXEntry.setIndexNames(*ifEntry.getIndexNames())
ifName = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1), DisplayString()).setMaxAccess("readonly")
ifInMulticastPkts = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 2), Counter32()).setMaxAccess("readonly")
ifInBroadcastPkts = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 3), Counter32()).setMaxAccess("readonly")
ifOutMulticastPkts = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 4), Counter32()).setMaxAccess("readonly")
ifOutBroadcastPkts = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 5), Counter32()).setMaxAccess("readonly")
ifHCInOctets = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6), Counter64()).setMaxAccess("readonly")
ifHCInUcastPkts = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 7), Counter64()).setMaxAccess("readonly")
ifHCInMulticastPkts = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 8), Counter64()).setMaxAccess("readonly")
ifHCInBroadcastPkts = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 9), Counter64()).setMaxAccess("readonly")
ifHCOutOctets = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 10), Counter64()).setMaxAccess("readonly")
ifHCOutUcastPkts = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 11), Counter64()).setMaxAccess("readonly")
ifHCOutMulticastPkts = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 12), Counter64()).setMaxAccess("readonly")
ifHCOutBroadcastPkts = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 13), Counter64()).setMaxAccess("readonly")
ifLinkUpDownTrapEnable = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 14), Integer32().subtype(subtypeSpec=ConstraintsUnion(SingleValueConstraint(1, 2,))).clone(namedValues=NamedValues(("enabled", 1), ("disabled", 2),))).setMaxAccess("readwrite")
ifHighSpeed = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 15), Gauge32()).setMaxAccess("readonly")
ifPromiscuousMode = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 16), TruthValue()).setMaxAccess("readwrite")
ifConnectorPresent = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 17), TruthValue()).setMaxAccess("readonly")
ifAlias = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 18), DisplayString().subtype(subtypeSpec=ValueSizeConstraint(0,64))).setMaxAccess("readwrite")
ifCounterDiscontinuityTime = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 19), TimeStamp()).setMaxAccess("readonly")
ifStackTable = MibTable((1, 3, 6, 1, 2, 1, 31, 1, 2), )
ifStackEntry = MibTableRow((1, 3, 6, 1, 2, 1, 31, 1, 2, 1), ).setIndexNames((0, "IF-MIB", "ifStackHigherLayer"), (0, "IF-MIB", "ifStackLowerLayer"))
ifStackHigherLayer = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 2, 1, 1), InterfaceIndexOrZero())
ifStackLowerLayer = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 2, 1, 2), InterfaceIndexOrZero())
ifStackStatus = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 2, 1, 3), RowStatus()).setMaxAccess("readcreate")
ifStackLastChange = MibScalar((1, 3, 6, 1, 2, 1, 31, 1, 6), TimeTicks()).setMaxAccess("readonly")
ifRcvAddressTable = MibTable((1, 3, 6, 1, 2, 1, 31, 1, 4), )
ifRcvAddressEntry = MibTableRow((1, 3, 6, 1, 2, 1, 31, 1, 4, 1), ).setIndexNames((0, "IF-MIB", "ifIndex"), (0, "IF-MIB", "ifRcvAddressAddress"))
ifRcvAddressAddress = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 4, 1, 1), PhysAddress())
ifRcvAddressStatus = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 4, 1, 2), RowStatus()).setMaxAccess("readcreate")
ifRcvAddressType = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 4, 1, 3), Integer32().subtype(subtypeSpec=ConstraintsUnion(SingleValueConstraint(1, 2, 3,))).clone(namedValues=NamedValues(("other", 1), ("volatile", 2), ("nonVolatile", 3),)).clone('volatile')).setMaxAccess("readcreate")
linkDown = NotificationType((1, 3, 6, 1, 6, 3, 1, 1, 5, 3)).setObjects(*(("IF-MIB", "ifIndex"), ("IF-MIB", "ifAdminStatus"), ("IF-MIB", "ifOperStatus"),))
linkUp = NotificationType((1, 3, 6, 1, 6, 3, 1, 1, 5, 4)).setObjects(*(("IF-MIB", "ifIndex"), ("IF-MIB", "ifAdminStatus"), ("IF-MIB", "ifOperStatus"),))
ifConformance = MibIdentifier((1, 3, 6, 1, 2, 1, 31, 2))
ifGroups = MibIdentifier((1, 3, 6, 1, 2, 1, 31, 2, 1))
ifCompliances = MibIdentifier((1, 3, 6, 1, 2, 1, 31, 2, 2))
ifCompliance3 = ModuleCompliance((1, 3, 6, 1, 2, 1, 31, 2, 2, 3)).setObjects(*(("IF-MIB", "ifGeneralInformationGroup"), ("IF-MIB", "linkUpDownNotificationsGroup"), ("IF-MIB", "ifFixedLengthGroup"), ("IF-MIB", "ifHCFixedLengthGroup"), ("IF-MIB", "ifPacketGroup"), ("IF-MIB", "ifHCPacketGroup"), ("IF-MIB", "ifVHCPacketGroup"), ("IF-MIB", "ifCounterDiscontinuityGroup"), ("IF-MIB", "ifRcvAddressGroup"),))
ifGeneralInformationGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 31, 2, 1, 10)).setObjects(*(("IF-MIB", "ifIndex"), ("IF-MIB", "ifDescr"), ("IF-MIB", "ifType"), ("IF-MIB", "ifSpeed"), ("IF-MIB", "ifPhysAddress"), ("IF-MIB", "ifAdminStatus"), ("IF-MIB", "ifOperStatus"), ("IF-MIB", "ifLastChange"), ("IF-MIB", "ifLinkUpDownTrapEnable"), ("IF-MIB", "ifConnectorPresent"), ("IF-MIB", "ifHighSpeed"), ("IF-MIB", "ifName"), ("IF-MIB", "ifNumber"), ("IF-MIB", "ifAlias"), ("IF-MIB", "ifTableLastChange"),))
ifFixedLengthGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 31, 2, 1, 2)).setObjects(*(("IF-MIB", "ifInOctets"), ("IF-MIB", "ifOutOctets"), ("IF-MIB", "ifInUnknownProtos"), ("IF-MIB", "ifInErrors"), ("IF-MIB", "ifOutErrors"),))
ifHCFixedLengthGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 31, 2, 1, 3)).setObjects(*(("IF-MIB", "ifHCInOctets"), ("IF-MIB", "ifHCOutOctets"), ("IF-MIB", "ifInOctets"), ("IF-MIB", "ifOutOctets"), ("IF-MIB", "ifInUnknownProtos"), ("IF-MIB", "ifInErrors"), ("IF-MIB", "ifOutErrors"),))
ifPacketGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 31, 2, 1, 4)).setObjects(*(("IF-MIB", "ifInOctets"), ("IF-MIB", "ifOutOctets"), ("IF-MIB", "ifInUnknownProtos"), ("IF-MIB", "ifInErrors"), ("IF-MIB", "ifOutErrors"), ("IF-MIB", "ifMtu"), ("IF-MIB", "ifInUcastPkts"), ("IF-MIB", "ifInMulticastPkts"), ("IF-MIB", "ifInBroadcastPkts"), ("IF-MIB", "ifInDiscards"), ("IF-MIB", "ifOutUcastPkts"), ("IF-MIB", "ifOutMulticastPkts"), ("IF-MIB", "ifOutBroadcastPkts"), ("IF-MIB", "ifOutDiscards"), ("IF-MIB", "ifPromiscuousMode"),))
ifHCPacketGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 31, 2, 1, 5)).setObjects(*(("IF-MIB", "ifHCInOctets"), ("IF-MIB", "ifHCOutOctets"), ("IF-MIB", "ifInOctets"), ("IF-MIB", "ifOutOctets"), ("IF-MIB", "ifInUnknownProtos"), ("IF-MIB", "ifInErrors"), ("IF-MIB", "ifOutErrors"), ("IF-MIB", "ifMtu"), ("IF-MIB", "ifInUcastPkts"), ("IF-MIB", "ifInMulticastPkts"), ("IF-MIB", "ifInBroadcastPkts"), ("IF-MIB", "ifInDiscards"), ("IF-MIB", "ifOutUcastPkts"), ("IF-MIB", "ifOutMulticastPkts"), ("IF-MIB", "ifOutBroadcastPkts"), ("IF-MIB", "ifOutDiscards"), ("IF-MIB", "ifPromiscuousMode"),))
ifVHCPacketGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 31, 2, 1, 6)).setObjects(*(("IF-MIB", "ifHCInUcastPkts"), ("IF-MIB", "ifHCInMulticastPkts"), ("IF-MIB", "ifHCInBroadcastPkts"), ("IF-MIB", "ifHCOutUcastPkts"), ("IF-MIB", "ifHCOutMulticastPkts"), ("IF-MIB", "ifHCOutBroadcastPkts"), ("IF-MIB", "ifHCInOctets"), ("IF-MIB", "ifHCOutOctets"), ("IF-MIB", "ifInOctets"), ("IF-MIB", "ifOutOctets"), ("IF-MIB", "ifInUnknownProtos"), ("IF-MIB", "ifInErrors"), ("IF-MIB", "ifOutErrors"), ("IF-MIB", "ifMtu"), ("IF-MIB", "ifInUcastPkts"), ("IF-MIB", "ifInMulticastPkts"), ("IF-MIB", "ifInBroadcastPkts"), ("IF-MIB", "ifInDiscards"), ("IF-MIB", "ifOutUcastPkts"), ("IF-MIB", "ifOutMulticastPkts"), ("IF-MIB", "ifOutBroadcastPkts"), ("IF-MIB", "ifOutDiscards"), ("IF-MIB", "ifPromiscuousMode"),))
ifRcvAddressGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 31, 2, 1, 7)).setObjects(*(("IF-MIB", "ifRcvAddressStatus"), ("IF-MIB", "ifRcvAddressType"),))
ifStackGroup2 = ObjectGroup((1, 3, 6, 1, 2, 1, 31, 2, 1, 11)).setObjects(*(("IF-MIB", "ifStackStatus"), ("IF-MIB", "ifStackLastChange"),))
ifCounterDiscontinuityGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 31, 2, 1, 13)).setObjects(*(("IF-MIB", "ifCounterDiscontinuityTime"),))
linkUpDownNotificationsGroup = NotificationGroup((1, 3, 6, 1, 2, 1, 31, 2, 1, 14)).setObjects(*(("IF-MIB", "linkUp"), ("IF-MIB", "linkDown"),))
ifTestTable = MibTable((1, 3, 6, 1, 2, 1, 31, 1, 3), )
ifTestEntry = MibTableRow((1, 3, 6, 1, 2, 1, 31, 1, 3, 1), )
ifEntry.registerAugmentions(("IF-MIB", "ifTestEntry"))
ifTestEntry.setIndexNames(*ifEntry.getIndexNames())
ifTestId = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 3, 1, 1), TestAndIncr()).setMaxAccess("readwrite")
ifTestStatus = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 3, 1, 2), Integer32().subtype(subtypeSpec=ConstraintsUnion(SingleValueConstraint(1, 2,))).clone(namedValues=NamedValues(("notInUse", 1), ("inUse", 2),))).setMaxAccess("readwrite")
ifTestType = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 3, 1, 3), AutonomousType()).setMaxAccess("readwrite")
ifTestResult = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 3, 1, 4), Integer32().subtype(subtypeSpec=ConstraintsUnion(SingleValueConstraint(1, 2, 3, 4, 5, 6, 7,))).clone(namedValues=NamedValues(("none", 1), ("success", 2), ("inProgress", 3), ("notSupported", 4), ("unAbleToRun", 5), ("aborted", 6), ("failed", 7),))).setMaxAccess("readonly")
ifTestCode = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 3, 1, 5), ObjectIdentifier()).setMaxAccess("readonly")
ifTestOwner = MibTableColumn((1, 3, 6, 1, 2, 1, 31, 1, 3, 1, 6), OwnerString()).setMaxAccess("readwrite")
ifGeneralGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 31, 2, 1, 1)).setObjects(*(("IF-MIB", "ifDescr"), ("IF-MIB", "ifType"), ("IF-MIB", "ifSpeed"), ("IF-MIB", "ifPhysAddress"), ("IF-MIB", "ifAdminStatus"), ("IF-MIB", "ifOperStatus"), ("IF-MIB", "ifLastChange"), ("IF-MIB", "ifLinkUpDownTrapEnable"), ("IF-MIB", "ifConnectorPresent"), ("IF-MIB", "ifHighSpeed"), ("IF-MIB", "ifName"),))
ifTestGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 31, 2, 1, 8)).setObjects(*(("IF-MIB", "ifTestId"), ("IF-MIB", "ifTestStatus"), ("IF-MIB", "ifTestType"), ("IF-MIB", "ifTestResult"), ("IF-MIB", "ifTestCode"), ("IF-MIB", "ifTestOwner"),))
ifStackGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 31, 2, 1, 9)).setObjects(*(("IF-MIB", "ifStackStatus"),))
ifOldObjectsGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 31, 2, 1, 12)).setObjects(*(("IF-MIB", "ifInNUcastPkts"), ("IF-MIB", "ifOutNUcastPkts"), ("IF-MIB", "ifOutQLen"), ("IF-MIB", "ifSpecific"),))
ifCompliance = ModuleCompliance((1, 3, 6, 1, 2, 1, 31, 2, 2, 1)).setObjects(*(("IF-MIB", "ifGeneralGroup"), ("IF-MIB", "ifStackGroup"), ("IF-MIB", "ifFixedLengthGroup"), ("IF-MIB", "ifHCFixedLengthGroup"), ("IF-MIB", "ifPacketGroup"), ("IF-MIB", "ifHCPacketGroup"), ("IF-MIB", "ifTestGroup"), ("IF-MIB", "ifRcvAddressGroup"),))
ifCompliance2 = ModuleCompliance((1, 3, 6, 1, 2, 1, 31, 2, 2, 2)).setObjects(*(("IF-MIB", "ifGeneralInformationGroup"), ("IF-MIB", "ifStackGroup2"), ("IF-MIB", "ifCounterDiscontinuityGroup"), ("IF-MIB", "ifFixedLengthGroup"), ("IF-MIB", "ifHCFixedLengthGroup"), ("IF-MIB", "ifPacketGroup"), ("IF-MIB", "ifHCPacketGroup"), ("IF-MIB", "ifRcvAddressGroup"),))
mibBuilder.exportSymbols("IF-MIB", ifAdminStatus=ifAdminStatus, ifSpecific=ifSpecific, ifHCInMulticastPkts=ifHCInMulticastPkts, ifIndex=ifIndex, ifTable=ifTable, ifXTable=ifXTable, ifTestStatus=ifTestStatus, ifCounterDiscontinuityTime=ifCounterDiscontinuityTime, ifCompliance3=ifCompliance3, ifMIB=ifMIB, ifEntry=ifEntry, ifHCOutBroadcastPkts=ifHCOutBroadcastPkts, ifHCPacketGroup=ifHCPacketGroup, ifHCInOctets=ifHCInOctets, ifNumber=ifNumber, ifTestOwner=ifTestOwner, ifTableLastChange=ifTableLastChange, ifRcvAddressAddress=ifRcvAddressAddress, PYSNMP_MODULE_ID=ifMIB, ifTestGroup=ifTestGroup, ifHCInUcastPkts=ifHCInUcastPkts, interfaces=interfaces, ifRcvAddressGroup=ifRcvAddressGroup, ifOutBroadcastPkts=ifOutBroadcastPkts, ifInUcastPkts=ifInUcastPkts, linkDown=linkDown, ifCompliance2=ifCompliance2, ifHighSpeed=ifHighSpeed, ifOutQLen=ifOutQLen, ifInErrors=ifInErrors, ifRcvAddressType=ifRcvAddressType, ifStackTable=ifStackTable, ifLastChange=ifLastChange, ifStackLastChange=ifStackLastChange, ifRcvAddressStatus=ifRcvAddressStatus, ifPacketGroup=ifPacketGroup, ifMtu=ifMtu, ifHCInBroadcastPkts=ifHCInBroadcastPkts, ifCompliances=ifCompliances, ifHCOutOctets=ifHCOutOctets, ifOperStatus=ifOperStatus, ifTestCode=ifTestCode, ifCompliance=ifCompliance, ifDescr=ifDescr, ifLinkUpDownTrapEnable=ifLinkUpDownTrapEnable, ifMIBObjects=ifMIBObjects, ifInDiscards=ifInDiscards, ifConformance=ifConformance, ifOutDiscards=ifOutDiscards, ifPromiscuousMode=ifPromiscuousMode, ifTestResult=ifTestResult, ifHCOutUcastPkts=ifHCOutUcastPkts, ifOutMulticastPkts=ifOutMulticastPkts, ifTestType=ifTestType, ifGroups=ifGroups, ifInOctets=ifInOctets, ifPhysAddress=ifPhysAddress, ifType=ifType, InterfaceIndex=InterfaceIndex, ifInUnknownProtos=ifInUnknownProtos, ifHCFixedLengthGroup=ifHCFixedLengthGroup, ifInNUcastPkts=ifInNUcastPkts, ifTestId=ifTestId, ifOutUcastPkts=ifOutUcastPkts, ifName=ifName, ifConnectorPresent=ifConnectorPresent, linkUp=linkUp, ifOutNUcastPkts=ifOutNUcastPkts, ifInMulticastPkts=ifInMulticastPkts, ifXEntry=ifXEntry, ifStackLowerLayer=ifStackLowerLayer, ifStackEntry=ifStackEntry, ifStackStatus=ifStackStatus, ifSpeed=ifSpeed, InterfaceIndexOrZero=InterfaceIndexOrZero, ifTestEntry=ifTestEntry, ifOutErrors=ifOutErrors, ifHCOutMulticastPkts=ifHCOutMulticastPkts, ifGeneralGroup=ifGeneralGroup, ifStackGroup=ifStackGroup, ifOldObjectsGroup=ifOldObjectsGroup, ifStackGroup2=ifStackGroup2, ifGeneralInformationGroup=ifGeneralInformationGroup, ifRcvAddressTable=ifRcvAddressTable, ifFixedLengthGroup=ifFixedLengthGroup, ifCounterDiscontinuityGroup=ifCounterDiscontinuityGroup, OwnerString=OwnerString, ifAlias=ifAlias, ifRcvAddressEntry=ifRcvAddressEntry, linkUpDownNotificationsGroup=linkUpDownNotificationsGroup, ifInBroadcastPkts=ifInBroadcastPkts, ifOutOctets=ifOutOctets, ifStackHigherLayer=ifStackHigherLayer, ifVHCPacketGroup=ifVHCPacketGroup, ifTestTable=ifTestTable)
