package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/akamensky/argparse"
	"github.com/rabidcicada/go-pcie-tlp/pcie"
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

func printfmttypes() {
	fmt.Printf("MRd3 % x\n", MRd3);
	fmt.Printf("MRd4 % x\n", MRd4);
	fmt.Printf("MRdLk3 % x\n", MRdLk3);
	fmt.Printf("MRdLk4 % x\n", MRdLk4);
	fmt.Printf("MWr3 % x\n", MWr3);
	fmt.Printf("MWr4 % x\n", MWr4);
	fmt.Printf("IORdT % x\n", IORdT);
	fmt.Printf("IOWrtT % x\n", IOWrtT);
	fmt.Printf("CfgRd0 % x\n", CfgRd0);
	fmt.Printf("CfgWr0 % x\n", CfgWr0);
	fmt.Printf("CfgRd1 % x\n", CfgRd1);
	fmt.Printf("CfgWr1 % x\n", CfgWr1);
	fmt.Printf("CplE % x\n", CplE);
	fmt.Printf("CplD % x\n", CplD);
	fmt.Printf("CplLk % x\n", CplLk);
	fmt.Printf("CplLkD % x\n", CplLkD);
	fmt.Printf("MRIOV % x\n", MRIOV);
	fmt.Printf("LocalVendPrefix % x\n", LocalVendPrefix);
	fmt.Printf("ExtTPH % x\n", ExtTPH);
	fmt.Printf("PASID % x\n", PASID);
	fmt.Printf("EndEndVendPrefix % x\n", EndEndVendPrefix);
}

func main() {
	all_tlp_types := []string{"MEMRD", "MEMWR", "CPL", "CFGWR"}
	// Create new parser object
	parser := argparse.NewParser("tlp-encode-decode", "encodes or decodes tlps")

	encode := parser.Flag("e", "encode", &argparse.Options{Required: false, Help: "Set if Encoding (as opposed to default decoding)"})
	printtypes := parser.Flag("p", "printtypes", &argparse.Options{Required: false, Help: "Print FMT/Type byte variations"})

	// Create string flag
	tlp_raw_bytes_str := parser.String("b", "bytes", &argparse.Options{Required: false, Help: "hexadecimal bytes of an expected tlp.  E.G. 08 08 00 60 FF 89 34 12 DD CC BB AA 18 AA FF EE CC CC CC CC FF FF FF FF'"})
	data_raw_bytes_str := parser.String("d", "data", &argparse.Options{Required: false, Help: "hexadecimal bytes of an expected tlp payload.  E.G. 08 08 00 60 FF 89 34 12 DD CC BB AA 18 AA FF EE CC CC CC CC FF FF FF FF'"})

	// TLP Type to Try
	var tlp_type *string = parser.Selector("t", "type", all_tlp_types, &argparse.Options{Required: false, Help: "The type of TLP transaction"})
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
	if *printtypes {
		printfmttypes();
		return
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
		default:
			panic("Unsupported type specified")
		}
	} else {
		fmt.Print("Parsing Decode Args\n")
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
		default:
			panic("Unsupported type specified")
		}
	} else {

		// Dispatch into parsers
		if *tlp_type == "" {
			try_decode(tlp_raw_bytes, all_tlp_types...)
		}else{
			try_decode(tlp_raw_bytes, *tlp_type)
		}

	}
}

func try_decode( tlp_raw_bytes []byte,  types ...string) {
	errs := []error{}

	for _,t := range types {
		switch t {
		case "MEMRD":
			tlp, err := pcie.NewMRdFromBytes(tlp_raw_bytes)
			if err != nil {
				errs = append(errs,fmt.Errorf("MEMRD: %w",err))
				continue
			}
			fmt.Print("Valid MEMRD Packet:" + hex.EncodeToString(tlp.ToBytes())+"\n")
			return
		case "MEMWR":
			tlp, err := pcie.NewMWrFromBytes(tlp_raw_bytes)
			if err != nil {
				errs = append(errs,fmt.Errorf("MEMWR: %w",err))
				continue
			}

			fmt.Print("Valid MEMWR Packet:" + hex.EncodeToString(tlp.ToBytes())+"\n")
			return
		case "CPL":
			tlp, err := pcie.NewCplFromBytes(tlp_raw_bytes)
			if err != nil {
				errs = append(errs,fmt.Errorf("CPL: %w",err))
				continue
			}

			fmt.Print("Valid CPL Packet:" + hex.EncodeToString(tlp.ToBytes())+"\n")
			return
		}
		
	}
	for _,err := range errs {
		fmt.Println(err.Error())
	}

}