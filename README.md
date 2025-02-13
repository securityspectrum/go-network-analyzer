This is a light-weight zeek-like network analyzer. 
The part which was inspired from zeek is mostly the 
connection caching based on tcp flags/states 
For original zeek source code, visit: https://github.com/zeek/zeek


Requirements: 
 - Requires npcap for Windows: https://npcap.com/dist/npcap-1.79.exe
 - Go 1.16 or higher

Downloads and removes unused modules/packages/dependencies with:
```
go mod tidy
```

Run the program from source code:
```
sudo go run . -verbose
```

To build a binary:

For windows:
```
GOOS=windows GOARCH=amd64 go build -o network-analyzer-win.exe . 
```

For macOS:
```
GOOS=darwin GOARCH=amd64 go build -o network-analyzer-darwin . 
chmod +x network-analyzer-darwin
./network-analyzer-darwin -verbose
```

For Linux:
```
GOOS=linux GOARCH=amd64 go build -o network-analyzer-linux . 
chmod +x network-analyzer-linux
./network-analyzer-linux -verbose
```