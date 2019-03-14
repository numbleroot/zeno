using Go = import "/go.capnp";
@0xf30bb9d3ef541f29;
$Go.package("messages");
$Go.import("github.com/numbleroot/zeno/messages");

struct Batch {
    comment @0 :Text;
}

interface Mix {
    acceptBatch @0 (batch :Batch) -> (ack :Text);
}
