# Gorip: Go Embed Extractor

## Overview

Gorip is a command-line tool written to extract and or locate embedded data from Golang binaries utilizing the 
`embed` package. This is currently very far from being polished so some things may not be working as intended.

> [!Note] 
> Due to the way Go embeds data, this tool only supports extraction of data embedded with `embed.FS` 
> at the moment. For more information regarding how the `embed` package embeds data can be found within this
> blog [post](https://0x00sec.org/t/extracting-go-embeds/34885)

## Usage

```bash
./gorip [options] <binary>
```

## Getting Started

### **Installation:**
1. Clone this repository: `git clone https://github.com/woesbot/gorip.git`
1. Change into the project directory: `cd gorip`
1. Build the executable: `go build .`
4. Run Gorip
   - Use the provided examples to extract the filesystem, generate manifest, or build a file tree from your Golang binary.

### Options:

- **-c, --chunk-size <size>**
  - Set chunk size in bytes (default: 16777216 (16 MB))

- **-e, --extract**
  - Extract candidates from the binary (default: false)

- **-m, --manifest**
  - Generate a candidate manifest for the binary (default: false)

- **-t, --tree**
  - Generate a file tree for the binary (default: false)

- **-v, --verbose**
  - Increase verbosity

### Examples:

`./gorip -c 1048576 -e ./path/to/binary`
- Sets the chunk size to 1MB and extracts embedded files to the invocation directory

`./gorip --manifest --tree ./path/to/binary`
- Generates a file manifest and file tree from the binary. The manifest and tree can be
found in the invocation directory under `./binary.tree` and `./binary.manifest`. Tree and Manifest output examples can be found in [examples/](/examples/)

## Contributing

If you encounter issues or have suggestions for improvement, feel free to open an issue or submit a pull request, any advice regarding code style/implementation helps.
