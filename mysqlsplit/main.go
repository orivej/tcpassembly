package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"orivej/tcpassembly/bidistream"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
	"github.com/orivej/e"
)

var nextID int

func NextID() int {
	nextID++
	return nextID
}

// splitStream implements bidistream.BidiStream
type splitStream struct {
	clientIndex uint8
	flowID      int
	lastIndex   uint8
	dirname     string
	data        []byte
	nextSize    int
	firstSeen   time.Time
}

func (s *splitStream) ReassemblyComplete() {}

func (s *splitStream) Reassembled(index uint8, rs []tcpassembly.Reassembly) {
	// tcpassembly batching without MaxBufferedPages = 1 may reorder client
	// and server streams.
	if s.firstSeen.IsZero() || s.firstSeen.After(rs[0].Seen) {
		s.firstSeen = rs[0].Seen
	}

	if index != s.clientIndex {
		return
	}

	for _, r := range rs {
		s.data = append(s.data, r.Bytes...)

		for {
			if s.nextSize == 0 && len(s.data) >= 4 {
				s.nextSize = int(4 + 0xFFFFFF&binary.LittleEndian.Uint32(s.data))
			}

			if s.nextSize == 0 || len(s.data) < s.nextSize {
				break
			}

			if s.data[4] == 3 { // Command: Query
				if len(s.dirname) == 0 {
					s.dirname = fmt.Sprintf("%08d-%v", s.flowID, s.firstSeen.UnixNano()/1000)
					err := os.Mkdir(s.dirname, 0777)
					e.Exit(err)
				}

				out, err := os.Create(fmt.Sprintf("%v/%v", s.dirname, r.Seen.UnixNano()/1000))
				e.Exit(err)
				defer e.CloseOrExit(out)
				_, err = out.Write(s.data[5:s.nextSize])
				e.Exit(err)
			}

			s.data = s.data[s.nextSize:]
			s.nextSize = 0
		}
	}
}

// splitStreamFactory implements bidistream.BidiStreamFactory for splitStream
type splitStreamFactory struct{}

var mysqlServerEndpoint = layers.NewTCPPortEndpoint(layers.TCPPort(3306))

func (f *splitStreamFactory) New(netFlow, tcpFlow gopacket.Flow) bidistream.BidiStream {
	s := &splitStream{flowID: NextID()}
	if tcpFlow.Src() == mysqlServerEndpoint {
		// Client stream is the other stream (stream 1) of the connection.
		s.clientIndex = 1
	}
	return s
}

func main() {
	flag.Parse()

	in, err := pcapgo.NewReader(os.Stdin)
	e.Exit(err)

	var (
		eth     layers.Ethernet
		ip4     layers.IPv4
		ip6     layers.IPv6
		tcp     layers.TCP
		payload gopacket.Payload
	)

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &payload)
	factory, factoryComplete := bidistream.NewStreamFactory(&splitStreamFactory{})
	streamPool := tcpassembly.NewStreamPool(factory)
	assembler := tcpassembly.NewAssembler(streamPool)

	decodedLayers := make([]gopacket.LayerType, 0, 10)

	for {
		data, ci, err := in.ReadPacketData()
		if err == io.EOF {
			assembler.FlushAll()
			factoryComplete()
			return
		}
		e.Exit(err)

		err = parser.DecodeLayers(data, &decodedLayers)
		e.Exit(err)

		for _, typ := range decodedLayers {
			switch typ {
			case layers.LayerTypeTCP:
				flow := tcp.TransportFlow()
				assembler.AssembleWithTimestamp(flow, &tcp, ci.Timestamp)
			}
		}
	}
}
