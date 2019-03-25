using Go = import "/go.capnp";
@0xa1ac1f9011521afa;
$Go.package("rpc");
$Go.import("github.com/numbleroot/zeno/rpc");

struct MixnetConfig {
    secondsToNextRound @0 :UInt16;
}

struct ConvoExitMsg {
    clientAddr @0 :Text;
    content @1 :Data;
}

struct ConvoMixMsg {
    pubKey @0 :Data;
    nonce @1 :Data;
    content @2 :Data;
}

struct Batch {
    msgs @0 :List(Data);
}

interface Mix {
    getMixnetConfig @0 () -> (meta :MixnetConfig);
    addConvoMsg @1 (msg :ConvoMixMsg) -> (status :UInt8);
    addBatch @2 (batch :Batch) -> (status :UInt8);
}
