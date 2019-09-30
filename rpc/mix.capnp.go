// Code generated by capnpc-go. DO NOT EDIT.

package rpc

import (
	capnp "zombiezen.com/go/capnproto2"
	text "zombiezen.com/go/capnproto2/encoding/text"
	schemas "zombiezen.com/go/capnproto2/schemas"
)

type EntryConvoMsg struct{ capnp.Struct }

// EntryConvoMsg_TypeID is the unique identifier for the type EntryConvoMsg.
const EntryConvoMsg_TypeID = 0x902882978134d105

func NewEntryConvoMsg(s *capnp.Segment) (EntryConvoMsg, error) {
	st, err := capnp.NewStruct(s, capnp.ObjectSize{DataSize: 0, PointerCount: 3})
	return EntryConvoMsg{st}, err
}

func NewRootEntryConvoMsg(s *capnp.Segment) (EntryConvoMsg, error) {
	st, err := capnp.NewRootStruct(s, capnp.ObjectSize{DataSize: 0, PointerCount: 3})
	return EntryConvoMsg{st}, err
}

func ReadRootEntryConvoMsg(msg *capnp.Message) (EntryConvoMsg, error) {
	root, err := msg.RootPtr()
	return EntryConvoMsg{root.Struct()}, err
}

func (s EntryConvoMsg) String() string {
	str, _ := text.Marshal(0x902882978134d105, s.Struct)
	return str
}

func (s EntryConvoMsg) Sender() (string, error) {
	p, err := s.Struct.Ptr(0)
	return p.Text(), err
}

func (s EntryConvoMsg) HasSender() bool {
	p, err := s.Struct.Ptr(0)
	return p.IsValid() || err != nil
}

func (s EntryConvoMsg) SenderBytes() ([]byte, error) {
	p, err := s.Struct.Ptr(0)
	return p.TextBytes(), err
}

func (s EntryConvoMsg) SetSender(v string) error {
	return s.Struct.SetText(0, v)
}

func (s EntryConvoMsg) PubKeyOrAddr() ([]byte, error) {
	p, err := s.Struct.Ptr(1)
	return []byte(p.Data()), err
}

func (s EntryConvoMsg) HasPubKeyOrAddr() bool {
	p, err := s.Struct.Ptr(1)
	return p.IsValid() || err != nil
}

func (s EntryConvoMsg) SetPubKeyOrAddr(v []byte) error {
	return s.Struct.SetData(1, v)
}

func (s EntryConvoMsg) Content() ([]byte, error) {
	p, err := s.Struct.Ptr(2)
	return []byte(p.Data()), err
}

func (s EntryConvoMsg) HasContent() bool {
	p, err := s.Struct.Ptr(2)
	return p.IsValid() || err != nil
}

func (s EntryConvoMsg) SetContent(v []byte) error {
	return s.Struct.SetData(2, v)
}

// EntryConvoMsg_List is a list of EntryConvoMsg.
type EntryConvoMsg_List struct{ capnp.List }

// NewEntryConvoMsg creates a new list of EntryConvoMsg.
func NewEntryConvoMsg_List(s *capnp.Segment, sz int32) (EntryConvoMsg_List, error) {
	l, err := capnp.NewCompositeList(s, capnp.ObjectSize{DataSize: 0, PointerCount: 3}, sz)
	return EntryConvoMsg_List{l}, err
}

func (s EntryConvoMsg_List) At(i int) EntryConvoMsg { return EntryConvoMsg{s.List.Struct(i)} }

func (s EntryConvoMsg_List) Set(i int, v EntryConvoMsg) error { return s.List.SetStruct(i, v.Struct) }

func (s EntryConvoMsg_List) String() string {
	str, _ := text.MarshalList(0x902882978134d105, s.List)
	return str
}

// EntryConvoMsg_Promise is a wrapper for a EntryConvoMsg promised by a client call.
type EntryConvoMsg_Promise struct{ *capnp.Pipeline }

func (p EntryConvoMsg_Promise) Struct() (EntryConvoMsg, error) {
	s, err := p.Pipeline.Struct()
	return EntryConvoMsg{s}, err
}

type ConvoMsg struct{ capnp.Struct }

// ConvoMsg_TypeID is the unique identifier for the type ConvoMsg.
const ConvoMsg_TypeID = 0xe4fb25d5577e606e

func NewConvoMsg(s *capnp.Segment) (ConvoMsg, error) {
	st, err := capnp.NewStruct(s, capnp.ObjectSize{DataSize: 0, PointerCount: 2})
	return ConvoMsg{st}, err
}

func NewRootConvoMsg(s *capnp.Segment) (ConvoMsg, error) {
	st, err := capnp.NewRootStruct(s, capnp.ObjectSize{DataSize: 0, PointerCount: 2})
	return ConvoMsg{st}, err
}

func ReadRootConvoMsg(msg *capnp.Message) (ConvoMsg, error) {
	root, err := msg.RootPtr()
	return ConvoMsg{root.Struct()}, err
}

func (s ConvoMsg) String() string {
	str, _ := text.Marshal(0xe4fb25d5577e606e, s.Struct)
	return str
}

func (s ConvoMsg) PubKeyOrAddr() ([]byte, error) {
	p, err := s.Struct.Ptr(0)
	return []byte(p.Data()), err
}

func (s ConvoMsg) HasPubKeyOrAddr() bool {
	p, err := s.Struct.Ptr(0)
	return p.IsValid() || err != nil
}

func (s ConvoMsg) SetPubKeyOrAddr(v []byte) error {
	return s.Struct.SetData(0, v)
}

func (s ConvoMsg) Content() ([]byte, error) {
	p, err := s.Struct.Ptr(1)
	return []byte(p.Data()), err
}

func (s ConvoMsg) HasContent() bool {
	p, err := s.Struct.Ptr(1)
	return p.IsValid() || err != nil
}

func (s ConvoMsg) SetContent(v []byte) error {
	return s.Struct.SetData(1, v)
}

// ConvoMsg_List is a list of ConvoMsg.
type ConvoMsg_List struct{ capnp.List }

// NewConvoMsg creates a new list of ConvoMsg.
func NewConvoMsg_List(s *capnp.Segment, sz int32) (ConvoMsg_List, error) {
	l, err := capnp.NewCompositeList(s, capnp.ObjectSize{DataSize: 0, PointerCount: 2}, sz)
	return ConvoMsg_List{l}, err
}

func (s ConvoMsg_List) At(i int) ConvoMsg { return ConvoMsg{s.List.Struct(i)} }

func (s ConvoMsg_List) Set(i int, v ConvoMsg) error { return s.List.SetStruct(i, v.Struct) }

func (s ConvoMsg_List) String() string {
	str, _ := text.MarshalList(0xe4fb25d5577e606e, s.List)
	return str
}

// ConvoMsg_Promise is a wrapper for a ConvoMsg promised by a client call.
type ConvoMsg_Promise struct{ *capnp.Pipeline }

func (p ConvoMsg_Promise) Struct() (ConvoMsg, error) {
	s, err := p.Pipeline.Struct()
	return ConvoMsg{s}, err
}

type Batch struct{ capnp.Struct }

// Batch_TypeID is the unique identifier for the type Batch.
const Batch_TypeID = 0xa7f59e6ee73e90ad

func NewBatch(s *capnp.Segment) (Batch, error) {
	st, err := capnp.NewStruct(s, capnp.ObjectSize{DataSize: 0, PointerCount: 1})
	return Batch{st}, err
}

func NewRootBatch(s *capnp.Segment) (Batch, error) {
	st, err := capnp.NewRootStruct(s, capnp.ObjectSize{DataSize: 0, PointerCount: 1})
	return Batch{st}, err
}

func ReadRootBatch(msg *capnp.Message) (Batch, error) {
	root, err := msg.RootPtr()
	return Batch{root.Struct()}, err
}

func (s Batch) String() string {
	str, _ := text.Marshal(0xa7f59e6ee73e90ad, s.Struct)
	return str
}

func (s Batch) Msgs() (ConvoMsg_List, error) {
	p, err := s.Struct.Ptr(0)
	return ConvoMsg_List{List: p.List()}, err
}

func (s Batch) HasMsgs() bool {
	p, err := s.Struct.Ptr(0)
	return p.IsValid() || err != nil
}

func (s Batch) SetMsgs(v ConvoMsg_List) error {
	return s.Struct.SetPtr(0, v.List.ToPtr())
}

// NewMsgs sets the msgs field to a newly
// allocated ConvoMsg_List, preferring placement in s's segment.
func (s Batch) NewMsgs(n int32) (ConvoMsg_List, error) {
	l, err := NewConvoMsg_List(s.Struct.Segment(), n)
	if err != nil {
		return ConvoMsg_List{}, err
	}
	err = s.Struct.SetPtr(0, l.List.ToPtr())
	return l, err
}

// Batch_List is a list of Batch.
type Batch_List struct{ capnp.List }

// NewBatch creates a new list of Batch.
func NewBatch_List(s *capnp.Segment, sz int32) (Batch_List, error) {
	l, err := capnp.NewCompositeList(s, capnp.ObjectSize{DataSize: 0, PointerCount: 1}, sz)
	return Batch_List{l}, err
}

func (s Batch_List) At(i int) Batch { return Batch{s.List.Struct(i)} }

func (s Batch_List) Set(i int, v Batch) error { return s.List.SetStruct(i, v.Struct) }

func (s Batch_List) String() string {
	str, _ := text.MarshalList(0xa7f59e6ee73e90ad, s.List)
	return str
}

// Batch_Promise is a wrapper for a Batch promised by a client call.
type Batch_Promise struct{ *capnp.Pipeline }

func (p Batch_Promise) Struct() (Batch, error) {
	s, err := p.Pipeline.Struct()
	return Batch{s}, err
}

const schema_a1ac1f9011521afa = "x\xda\x8c\x90\xbfJ+A\x14\x87\xcfo&{\x93\"" +
	"\xff\x96Mu\xb9\x17\x1b\x03\x89\xf8\x87@\x0aIab" +
	"B@1bF\x04-\x8d\x9b%*dv\xd9]\xa3" +
	"i\x14}\x82tv\x8266\x8a\xbd]\x0a\x0bK\x0b" +
	"_@\x04\x9f \x85\x8a\xacl\xd4(\xa9\xec\xce\x1c>" +
	"\x0e\xdf7\xf1n\x81e\x14\x93\x11\x89\x7f\xca\x1fO\xb9" +
	"\xcb\x1e\x1e\x1f\xa5:\xa4F\xe1\xbd\xfc]V;#\x17" +
	"\xa7\xa4\xf0 \x91\xf6\x1f\x0fZ\x1a\xfe\x94\xc4\x15\xc1\xbb" +
	"\xec\xcc<\xc9\x93\xde\xf9\x10\xdb'\xba8\xd3n\xfb\xd3" +
	"\x0d\xf2\x04O\xae\xef\xaf\xde'_\x1f\x87X\xe6\x13=" +
	"\\ko}\xf6\x19\xbb4\xe1\xd9\x96>\xd5\xdc\xda\x9b" +
	"dz\xcd\x92V\xae,]\xbb]2e\xcb\x0c.:" +
	"\x8d* \xc2<@\x14\x00\x91Z\xce\x11\x89\x02\x87\xa8" +
	"0\xa8@\x02\xfer~\x9bH\xccq\x88\x15\x06\x95\xb1" +
	"\x04\x18\x91*\x8aD\xa2\xc2!\xd6\x18\xf2\x8e!\xeb\x86" +
	"\x8d01\x84\x09\x9e\xb5\xb3\xb1`\xb4\x97l\x8a\xcd\xd6" +
	"\xeb6\"\xc4\x10!\x1c\xe8\xa6t\x0d\xe9~\xbd\x07^" +
	"\xf8\xf0*\xd6\x82\xae\xbe\xe9\xfb\x04\x06>\x911\"\x11" +
	"\xe2\x10\xa3\x0c\xb1\xa6\xd3p\x10%T9\x10\xff\xfe\x01" +
	"\x82\xbf\x1c\xbeV2\xf3\xb2e~\x06\x86\x06\x07\xd3~" +
	"K\x8aCd\x7f\x04f\xfc\x96q\x0e1\xcd~+\xff" +
	"\x1e\x00\x00\xff\xff\x0b\x8dq\xc4"

func init() {
	schemas.Register(schema_a1ac1f9011521afa,
		0x902882978134d105,
		0xa7f59e6ee73e90ad,
		0xe4fb25d5577e606e)
}
