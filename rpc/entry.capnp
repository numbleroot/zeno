using Go = import "/go.capnp";
@0xa1ac1f9011521afa;
$Go.package("rpc");
$Go.import("github.com/numbleroot/zeno/rpc");

struct MixnetConfig {
    secondsToNextRound @0 :UInt16;
}

struct ConvoMsg {
    content @0 :Data;
}

interface EntryMix {
    getMixnetConfig @0 () -> (meta :MixnetConfig);
    addConvoMsg @1 (msg :ConvoMsg) -> (status :UInt8);
}
