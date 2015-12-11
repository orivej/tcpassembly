package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"orivej/tcpassembly/bidistream"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
	"github.com/orivej/e"
)

var flSaveResponses = flag.Bool("s", false, "save query responses")

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
	data        [2][]byte
	seen        [2]time.Time
	nextSize    int
	firstSeen   time.Time
}

func (s *splitStream) ensureDir() {
	if len(s.dirname) == 0 {
		s.dirname = fmt.Sprintf("%08d-%v", s.flowID, s.firstSeen.UnixNano()/1000)
		err := os.Mkdir(s.dirname, 0777)
		e.Exit(err)
	}
}

func (s *splitStream) write(name string, mtime time.Time, data []byte) {
	s.ensureDir()

	fname := filepath.Join(s.dirname, name)
	out, err := os.Create(fname)
	e.Exit(err)
	_, err = out.Write(data)
	e.Exit(err)
	err = out.Close()
	e.Exit(err)
	err = os.Chtimes(fname, mtime, mtime)
	e.Exit(err)
}

func (s *splitStream) writeResponses() {
	index := 1 - s.clientIndex
	if len(s.data[index]) == 0 {
		return
	}
	ts := s.seen[index]
	fname := fmt.Sprintf("%vo", ts.UnixNano()/1000)
	s.write(fname, ts, s.data[index])

	s.data[index] = s.data[index][0:0]
	s.seen[index] = time.Time{}
}

func (s *splitStream) Reassembled(index uint8, rs []tcpassembly.Reassembly) {
	if s.firstSeen.IsZero() {
		s.firstSeen = rs[0].Seen
	}

	isClient := index == s.clientIndex

	if !isClient && !*flSaveResponses {
		return
	}

	for _, r := range rs {
		s.data[index] = append(s.data[index], r.Bytes...)

		if s.seen[index].IsZero() {
			s.seen[index] = r.Seen
		}

		if !isClient {
			continue
		}

		for {
			if s.nextSize == 0 && len(s.data[index]) >= 4 {
				s.nextSize = int(4 + 0xFFFFFF&binary.LittleEndian.Uint32(s.data[index]))
			}

			if s.nextSize == 0 || len(s.data[index]) < s.nextSize {
				break
			}

			if s.data[index][4] == 3 { // Command: Query
				fname := fmt.Sprintf("%v", r.Seen.UnixNano()/1000)
				s.write(fname, r.Seen, s.data[index][5:s.nextSize])
			}

			s.data[index] = s.data[index][s.nextSize:]
			s.nextSize = 0
		}
	}

	if isClient && *flSaveResponses {
		s.writeResponses()
	}
}

func (s *splitStream) ReassemblyComplete() {
	if *flSaveResponses {
		s.writeResponses()
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
		netFlow gopacket.Flow
	)

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &payload)
	factory, factoryComplete := bidistream.NewStreamFactory(&splitStreamFactory{})
	streamPool := tcpassembly.NewStreamPool(factory)
	assembler := tcpassembly.NewAssembler(streamPool)
	assembler.AssemblerOptions.MaxBufferedPagesTotal = 1

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
			case layers.LayerTypeIPv4:
				netFlow = ip4.NetworkFlow()
			case layers.LayerTypeIPv6:
				netFlow = ip6.NetworkFlow()
			case layers.LayerTypeTCP:
				assembler.AssembleWithTimestamp(netFlow, &tcp, ci.Timestamp)
			}
		}
	}
}
