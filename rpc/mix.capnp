using Go = import "/go.capnp";
@0xa1ac1f9011521afa;
$Go.package("rpc");
$Go.import("github.com/numbleroot/zeno/rpc");

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
    addConvoMsg @0 (msg :ConvoMixMsg) -> (status :UInt8);
    addBatch @1 (batch :Batch) -> (status :UInt8);
}
