# pktwatch

pktwatch is a network packet capture tool that allows you to monitor and analyze network traffic in real-time. It supports both command-line and graphical user interface (GUI) modes.

## Features

- Capture packets from network devices
- Display captured packets in real-time
- Filter packets using include and exclude patterns
- Export captured packets to a file
- GUI mode for an enhanced user experience
- Verbose mode for detailed packet information

## Installation

### Using the Binary

1. Download the latest release from the [releases page](https://github.com/EwanClark/pktwatch/releases).
2. Extract the downloaded archive.
3. Move the binary to a directory in your PATH, for example `/usr/local/bin`:

    ```sh
    sudo mv pktwatch /usr/local/bin/
    ```

4. Ensure the binary is executable:

    ```sh
    sudo chmod +x /usr/local/bin/pktwatch
    ```

5. Run the binary:

    ```sh
    pktwatch
    ```

### Building with Cargo

1. Ensure you have [Rust](https://www.rust-lang.org/tools/install) installed.
2. Clone the repository:

    ```sh
    git clone https://github.com/EwanClark/pktwatch.git
    cd pktwatch
    ```

3. Build the project using Cargo:

    ```sh
    cargo build --release
    ```

4. Move the binary to a directory in your PATH, for example `/usr/local/bin`:

    ```sh
    sudo mv target/release/pktwatch /usr/local/bin/
    ```

5. Ensure the binary is executable:

    ```sh
    sudo chmod +x /usr/local/bin/pktwatch
    ```

6. Run the binary:

    ```sh
    pktwatch
    ```

## Usage

### Command-Line Options

- `-p, --promisc` : Captures all packets on the network.
- `-g, --gui` : Shows a graphical interface in the terminal.
- `-e, --export <FILE>` : Export captured packets to a file.
- `-c, --clear` : Clears the file before exporting.
- `-v, --verbose` : Enable verbose output.
- `-V, --version` : Show version information.
- `-f, --filter <PATTERN>` : Filter packets using patterns (semicolon-separated). Include with pattern, exclude with !pattern.

### Example

Capture packets in promiscuous mode and export them to a file:

    pktwatch -p -e packets.txt
    

Run in GUI mode:

    pktwatch -g
    
