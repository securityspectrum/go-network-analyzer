This is a light-weight zeek-like network analyzer.

Requirements: 
 - Requires npcap for Windows: https://npcap.com/dist/npcap-1.79.exe
 - Go 1.16 or higher

Downloads and removes unused modules/packages/dependencies with:
```
go mod tidy
```

Run the program from source code:
```
go run main.go types.go strategy.go connection.go device_manager.go -verbose
```

To build a binary:

For windows:
```
GOOS=windows GOARCH=amd64 go build -o network-analyzer-win.exe main.go types.go strategy.go connection.go device_manager.go
```

For macOS:
```
GOOS=darwin GOARCH=amd64 go build -o network-analyzer-darwin main.go types.go strategy.go connection.go device_manager.go
chmod +x network-analyzer-darwin
./network-analyzer-darwin -verbose
chmod +x network-analyzer-darwin
./network-analyzer-darwin -verbose
```

For Linux:
```
GOOS=linux GOARCH=amd64 go build -o network-analyzer-linux main.go types.go strategy.go connection.go device_manager.go
chmod +x network-analyzer-linux
./network-analyzer-linux -verbose
```