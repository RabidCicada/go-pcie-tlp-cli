package cli

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/akamensky/argparse"
	"github.com/google/go-pcie-tlp/pcie"
)

const (
	fmt3DWNoData   = 0b000
	fmt4DWNoData   = 0b001
	fmt3DWWithData = 0b010
	fmt4DWWithData = 0b011
	fmtTlpPrefix   = 0b100
)

// TlpType is the format and type field in the TLP header.
// See Table 2-3 in PCI EXPRESS BASE SPECIFICATION, REV. 3.1a.
type TlpType uint8

const (
	// MRd3 is a Memory Read Request encoded with 3 dwords.
	MRd3 TlpType = (fmt3DWNoData << 5) | 0b00000
	// MRd4 is a Memory Read Request encoded with 4 dwords.
	MRd4 TlpType = (fmt4DWNoData << 5) | 0b00000
	// MRdLk3 is a Memory Read Request-Locked encoded with 3 dwords.
	MRdLk3 TlpType = (fmt3DWNoData << 5) | 0b00001
	// MRdLk4 is a Memory Read Request-Locked encoded with 4 dwords.
	MRdLk4 TlpType = (fmt4DWNoData << 5) | 0b00001
	// MWr3 is a Memory Write Request encoded with 3 dwords.
	MWr3 TlpType = (fmt3DWWithData << 5) | 0b00000
	// MWr4 is a Memory Write Request encoded with 4 dwords.
	MWr4 TlpType = (fmt4DWWithData << 5) | 0b00000
	// IORdT is an I/O Read Request.
	IORdT TlpType = (fmt3DWNoData << 5) | 0b00010
	// IOWrtT is an I/O Write Request.
	IOWrtT TlpType = (fmt3DWWithData << 5) | 0b00010
	// CfgRd0 is a Configuration Read of Type 0.
	CfgRd0 TlpType = (fmt3DWNoData << 5) | 0b00100
	// CfgWr0 is a Configuration Write of Type 0.
	CfgWr0 TlpType = (fmt3DWWithData << 5) | 0b00100
	// CfgRd1 is a Configuration Read of Type 1.
	CfgRd1 TlpType = (fmt3DWNoData << 5) | 0b00101
	// CfgWr1 is a Configuration Write of Type 1.
	CfgWr1 TlpType = (fmt3DWWithData << 5) | 0b00101
	// CplE is a Completion without Data. Used for I/O and
	// Configuration Write Completions with any
	// Completion Status.
	CplE TlpType = (fmt3DWNoData << 5) | 0b01010
	// CplD is a Completion with Data. Used for Memory,
	// I/O, and Configuration Read Completions.
	CplD TlpType = (fmt3DWWithData << 5) | 0b01010
	// CplLk is a Completion for Locked Memory Read without
	// Data. Used only in error case.
	CplLk TlpType = (fmt3DWNoData << 5) | 0b01011
	// CplLkD is a Completion for Locked Memory Read –
	// otherwise like CplD.
	CplLkD TlpType = (fmt3DWWithData << 5) | 0b01011
	// MRIOV is a Multi-Root I/O Virtualization and Sharing (MR-IOV) TLP prefix.
	MRIOV TlpType = (fmtTlpPrefix << 5) | 0b00000
	// LocalVendPrefix is a Local TLP prefix with vendor sub-field.
	LocalVendPrefix TlpType = (fmtTlpPrefix << 5) | 0b01110
	// ExtTPH is an Extended TPH TLP prefix.
	ExtTPH TlpType = (fmtTlpPrefix << 5) | 0b10000
	// PASID is a Process Address Space ID (PASID) TLP Prefix.
	PASID TlpType = (fmtTlpPrefix << 5) | 0b10001
	// EndEndVendPrefix is an End-to-End TLP prefix with vendor sub-field.
	EndEndVendPrefix TlpType = (fmtTlpPrefix << 5) | 0b11110
)

func printBytes(s []byte) {
	fmt.Printf("% x", printBytes)
}

func main() {
	// Create new parser object
	parser := argparse.NewParser("tlp-encode-decode", "encodes or decodes tlps")

	encode := parser.Flag("e", "encode", &argparse.Options{Required: false, Help: "Set if Encoding (as opposed to default decoding)"})

	// Create string flag
	tlp_raw_bytes_str := parser.String("b", "bytes", &argparse.Options{Required: false, Help: "hexadecimal bytes of an expected tlp.  E.G. 08 08 00 60 FF 89 34 12 DD CC BB AA 18 AA FF EE CC CC CC CC FF FF FF FF'"})
	data_raw_bytes_str := parser.String("d", "data", &argparse.Options{Required: false, Help: "hexadecimal bytes of an expected tlp payload.  E.G. 08 08 00 60 FF 89 34 12 DD CC BB AA 18 AA FF EE CC CC CC CC FF FF FF FF'"})

	// TLP Type to Try
	var tlp_type *string = parser.Selector("t", "type", []string{"MEMRD", "MEMWR"}, &argparse.Options{Required: true, Help: "The type of TLP transaction"})
	var device_id_str *string = parser.String("", "did", &argparse.Options{Required: false, Help: "Device ID in form of '<busnum>:<devicenum>:<funcnum>'"})
	tag := parser.Int("", "tag", &argparse.Options{Required: false, Help: "uint8_t tag number"})
	addr_str := parser.String("", "addr", &argparse.Options{Required: false, Help: "Non-0x-prefixed hexadecimal address"})
	length := parser.Int("", "len", &argparse.Options{Required: false, Help: "number of bytes for the transaction (MemRd/MemWr)"})

	// Parse input
	err := parser.Parse(os.Args)
	if err != nil {
		// In case of error print error and print usage
		// This can also be done by passing -h or --help flags
		fmt.Print(parser.Usage(err))
		os.Exit(1)
	}

	var tlp_raw_bytes []byte
	var data_raw_bytes []byte

	var addr uint64
	var did pcie.DeviceID

	// Parse req args
	if *encode {

		switch *tlp_type {
		case "MEMWR":
			spaceless_data_raw_bytes_str := strings.ReplaceAll(*data_raw_bytes_str, " ", "")

			data_raw_bytes, err = hex.DecodeString(spaceless_data_raw_bytes_str)
			if err != nil {

				panic(err)
			}
			fallthrough
		case "MEMRD":
			err := did.FromString(*device_id_str)
			if err != nil {
				panic(err)
			}
			addr, err = strconv.ParseUint(*addr_str, 16, 64)
			if err != nil {

				panic(err)
			}
		}
	} else {
		fmt.Print("Parsing Decode Args")
		spaceless_tlp_raw_bytes_str := strings.ReplaceAll(*tlp_raw_bytes_str, " ", "")

		tlp_raw_bytes, err = hex.DecodeString(spaceless_tlp_raw_bytes_str)
		if err != nil {

			panic(err)
		}

	}

	if *encode {
		// Dispatch into encoders/creators
		switch *tlp_type {
		case "MEMRD":
			tlp, err := pcie.NewMRd(did, uint8(*tag), addr, uint32(*length))
			if err != nil {
				panic(err)
			}
			fmt.Print(hex.EncodeToString(tlp.ToBytes()))
		case "MEMWR":
			tlp, err := pcie.NewMWr(did, addr, data_raw_bytes)
			if err != nil {
				panic(err)
			}
			fmt.Printf("Did: 0x%04x\n", did.ToUint16())
			fmt.Printf("tag: 0x%02x\n", uint8(*tag))
			fmt.Print(hex.EncodeToString(tlp.ToBytes()))
			fmt.Printf("\nMWr3 as uint8==>%02x\n",uint8(MWr3))
			fmt.Printf("\nMWr4 as uint8==>%02x\n",uint8(MWr4))
		}
	} else {

		// Dispatch into parsers
		switch *tlp_type {
		case "MEMRD":
			tlp, err := pcie.NewMRdFromBytes(tlp_raw_bytes)
			if err != nil {
				panic(err)
			}
			fmt.Print(hex.EncodeToString(tlp.ToBytes()))
		case "MEMWR":
			tlp, err := pcie.NewMWrFromBytes(tlp_raw_bytes)
			if err != nil {
				panic(err)
			}

			fmt.Print(hex.EncodeToString(tlp.ToBytes()))
		}
	}
}
