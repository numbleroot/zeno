package mixnet

import (
	"fmt"
	"net"

	"github.com/numbleroot/zeno/rpc"
	capnprpc "zombiezen.com/go/capnproto2/rpc"
)

func (mix *EntryMix) GetMixnetConfig(call rpc.EntryMix_getMixnetConfig) error {

	fmt.Printf("\nGetMixnetConfig req.\n")

	call.Results.SetMeta(rpc.MixnetConfig{})

	return nil
}

func (mix *EntryMix) AddConvoMsg(call rpc.EntryMix_addConvoMsg) error {

	msg, err := call.Params.Msg()
	if err != nil {
		return err
	}

	fmt.Printf("\nAddConvoMsg req: '%#v'\n", msg)

	call.Results.SetStatus(0)

	return nil
}

func (mix *EntryMix) HandleMsg(c net.Conn) {

	main := rpc.EntryMix_ServerToClient(mix)
	conn := capnprpc.NewConn(capnprpc.StreamTransport(c), capnprpc.MainInterface(main.Client))

	err := conn.Wait()
	if err != nil {
		fmt.Printf("Error waiting for public connection: %v\n", err)
	}
}
