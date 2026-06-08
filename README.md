# Nano V5 Scanner
# Nano V5 - Network Scanner & Banner Grabber

A fast, concurrent network scanner and banner grabbing tool written in Go.

## 🚀 Quick Installation

You can install **Nano V5** directly using the Go CLI. Copy and paste the command below into your terminal:

```bash
go install :https://github.com/lancelotfxx-spec/nanov5-scanner.git
```

*Note: Make sure your `$GOPATH/bin` is added to your system's PATH environment variable so you can run the tool from anywhere.*

### 🛠️ Manual Installation (Alternative)

If you prefer to clone the repository and build it manually, use these commands:

```bash
# Clone the repository
git clone https:https://github.com/lancelotfxx-spec/nanov5-scanner.git

# Change directory
cd nanov5-scanner

# Download dependencies
go get golang.org/x/net/icmp

# Run the scanner
go run main.go -t 127.0.0.1
```

## 📖 Usage Examples

Here are some quick command examples you can copy and use:

```bash
# Scan a standard domain website
nano-v5 -t google.com

# Scan specific ports on a target
nano-v5 -t 192.168.1.1 -p 22,80,443

# Scan a full network CIDR range with 100 threads
sudo nano-v5 -t 192.168.1.0/24 -c 100
```
