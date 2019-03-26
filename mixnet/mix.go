package mixnet

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"

	"github.com/numbleroot/zeno/rpc"
	capnprpc "zombiezen.com/go/capnproto2/rpc"
)

// AddCoverMsgsToPool ensures that a reasonable
// (usually, #clients / 10) amount of generated
// cover messages is prepopulated in the message
// pool of each mix. We aim to thwart n - 1 attacks
// by choosing forward batch messages uniformly
// at random from that pool with the exception of
// old messages.
func (mix *Mix) AddCoverMsgsToPool() error {

	// Determine number of clients and
	// respective sample size.
	numClients := int64(len(mix.KnownClients))
	numSamples := numClients / 10
	if numSamples < 100 {
		numSamples = numClients
	}

	recipients := make([]*Endpoint, numSamples)

	// Randomly select k clients to generate
	// cover messages to.
	for i := range recipients {

		// Select a user index uniformly at random.
		chosenBig, err := rand.Int(rand.Reader, big.NewInt(numClients))
		if err != nil {
			return err
		}
		chosen := chosenBig.Int64()

		// Incorporate client chosen by CSPRNG
		// into list of recipients.
		recipients[i] = mix.KnownClients[chosen]
	}

	// TODO: Construct symmetric keys to recipients.

	// TODO: For each recipient:

	//       TODO: Generate ConvoExitMsg with random message.

	//       TODO: Onion-encrypt created msg in ConvoMixMsgs.

	//       TODO: Add layered ConvoMixMsg to pool in first time slot.

	return nil
}

func (mix *Mix) AddBatch(call rpc.Mix_addBatch) error {

	data, err := call.Params.Batch()
	if err != nil {
		return err
	}

	fmt.Printf("\nAddBatch req: '%#v'\n", data)

	call.Results.SetStatus(0)

	return nil
}

func (mix *Mix) GetMixnetConfig(call rpc.Mix_getMixnetConfig) error {

	fmt.Printf("\nGetMixnetConfig req.\n")

	call.Results.SetMeta(rpc.MixnetConfig{})

	return nil
}

func (mix *Mix) AddConvoMsg(call rpc.Mix_addConvoMsg) error {

	msg, err := call.Params.Msg()
	if err != nil {
		return err
	}

	fmt.Printf("\nAddConvoMsg req: '%#v'\n", msg)

	call.Results.SetStatus(0)

	return nil
}

func (mix *Mix) HandleMsg(c net.Conn) {

	main := rpc.Mix_ServerToClient(mix)
	conn := capnprpc.NewConn(capnprpc.StreamTransport(c), capnprpc.MainInterface(main.Client))

	err := conn.Wait()
	if err != nil {
		fmt.Printf("Error waiting for public connection: %v\n", err)
	}
}
