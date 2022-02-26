using Go = import "/go.capnp";
$Go.package("fastnetmon");
$Go.import("fastnetmon/simplepacket");

@0xa8a892437a5fd28f;

# Call script  ../scripts/capnp_bindings_generator.py for regeneration

struct SimplePacketType {
    source @0 :UInt8;
    sampleRatio @1 :UInt32;
    srcIp @2 :UInt32;
    dstIp @3 :UInt32;
    srcIpv6 @4 :Data;
    dstIpv6 @5 :Data;
    srcAsn @6 :UInt32;
    dstAsn @7 :UInt32;
    inputInterface @8 :UInt32;
    outputInterface @9 :UInt32;
    ipProtocolVersion @10 :UInt8;
    ttl @11 :UInt8;
    sourcePort @12 :UInt16;
    destinationPort @13 :UInt16;
    protocol @14 :UInt32;
    length @15 :UInt64;
    numberOfPackets @16 :UInt64;
    flags @17 :UInt8;
    ipFragmented @18 :Bool;
    ipDontFragment @19 :Bool;
    tsSec @20 :Int64;
    tsMsec @21 :Int64;
    packetPayloadLength @22 :Int32;
    packetPayloadFullLength @23 :UInt32;
    packetDirection @24 :UInt8;
    agentIpAddress @25 :UInt32;
}
