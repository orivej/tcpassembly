// Package bidistream provides bidirectional TCP stream reassembly.
//
// Bidirection TCP reassembly in general is protocol specific.  This reassembler
// works for protocols those endpoints at any moment are either readers or
// writers, and change their role only in response to writes from the other
// endpoint.
//
// For each flow, a user-supplied BidiStreamFactory will create a
// user-implemented BidiStream.
package bidistream

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
)

type BidiStream interface {
	// Reassembled is called with an endpoint number (0 or 1) and packets in
	// the reassembled order.
	Reassembled(uint8, []tcpassembly.Reassembly)
	ReassemblyComplete()
}

type BidiStreamFactory interface {
	New(netFlow, tcpFlow gopacket.Flow) BidiStream
}

type key struct {
	net, transport gopacket.Flow
}

type myStream struct {
	index uint8
	bidi  *bidi
	done  bool
}

type bidi struct {
	a, b *myStream
	s    BidiStream
}

type bidiFactory struct {
	bidiMap     map[key]*bidi
	userFactory BidiStreamFactory
}

func NewStreamFactory(userFactory BidiStreamFactory) (tcpassembly.StreamFactory, func()) {
	f := &bidiFactory{map[key]*bidi{}, userFactory}
	return f, f.Complete
}

func (f *bidiFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	s := &myStream{}
	k := key{netFlow, tcpFlow}
	bd := f.bidiMap[k]
	if bd == nil {
		bd = &bidi{a: s, s: f.userFactory.New(netFlow, tcpFlow)}
		f.bidiMap[key{netFlow.Reverse(), tcpFlow.Reverse()}] = bd
	} else {
		s.index = 1
		bd.b = s
		delete(f.bidiMap, k)
	}
	s.bidi = bd
	return s

}

func (f *bidiFactory) Complete() {
	for k := range f.bidiMap {
		f.bidiMap[k].s.ReassemblyComplete()
		delete(f.bidiMap, k)
	}
}

func (s *myStream) Reassembled(rs []tcpassembly.Reassembly) {
	s.bidi.s.Reassembled(s.index, rs)
}

func (s *myStream) ReassemblyComplete() {
	s.done = true
	bd := s.bidi
	if bd.b != nil && bd.a.done && bd.b.done {
		bd.s.ReassemblyComplete()
	}
}
