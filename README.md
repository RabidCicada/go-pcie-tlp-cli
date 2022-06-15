# go-pcie-tlp-cli
A slapdash cli using go-pcie-tlp

Currently only supports MEMRD and MEMWR.  Other types are coming.  As is better code :).

# To Use
-  clone codebase
-  cd into pcie-tlp-cli
-  go mod init pcie-tlp-cli.go
-  go tidy
-  go run pcie-tlp-cli.go <args>

# Parsing

The only intent of parsing a byte stream of a tlp currently is to check it is well formed.  It will echo the bytestream if valid.  It will throw an error if invalid.
It's current function is only as a debugging tool to check that it is well formed.

# Creating/Packing

The intent of Creating/packing is to demonstrate the correct tlp byte stream for the given arguments.

# Example of parsing an existing byte capture trying to decode as a memory write

`go run pcie-tlp-cli.go --type MEMWR -b "60000002032400ff18aaffeeddccbba8ccccccccffffffff"`

If the bytestream is invalid the tool should spit out an error stating which field is invalid
# Example of parsing an existing byte capture trying to decode as a memory read

`go run pcie-tlp-cli.go --type MEMWR -b "20000002032489ff18aaffeeddccbba8"`

If the bytestream is invalid the tool should spit out an error stating which field is invalid

# Example of generating a tlp byte array by feeding arguments

`go run tlpdecode.go -e --type MEMWR -d "cc cc cc cc ff ff ff ff" --did 03:04.4 --tag 137 --addr "18aaffeeddccbbaa" --len 8"`

`go run tlpdecode.go -e --type MEMRD --did 03:04.4 --tag 137 --addr "18aaffeeddccbbaa" --len 8"`


# Known bugs
- Currently the upstream [go-pcie-tlp](https://github.com/google/go-pcie-tlp) codebase automatically sets tag to 0 regardless of passing in a tag.  It is ignored.

# Future Improvments
- Add english language printing of the fields in the TLP for Parsing correct byte arrays instead of echo of byte array