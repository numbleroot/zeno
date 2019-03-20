using Go = import "/go.capnp";
@0xf30bb9d3ef541f29;
$Go.package("rpc");
$Go.import("github.com/numbleroot/zeno/rpc");

struct Batch {
    msgs @0 :List(Data);
}

interface CommonMix {
    addBatch @0 (batch :Batch) -> (status :UInt8);
}
