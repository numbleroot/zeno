using Go = import "/go.capnp";
@0xa1ac1f9011521afa;
$Go.package("rpc");
$Go.import("github.com/numbleroot/zeno/rpc");

struct ConvoMsg {
    pubKeyOrAddr @0 :Data;
    content @1 :Data;
}

struct Batch {
    msgs @0 :List(ConvoMsg);
}

interface Mix {
    addConvoMsg @0 (msg :ConvoMsg) -> (status :UInt8);
    addBatch @1 (batch :Batch) -> (status :UInt8);
}
