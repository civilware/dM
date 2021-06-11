# dM (DERO Message)
For testnet purposes: I recommend generating a new client wallet to host the service. Just to confirm no other services/dApps have used the ports defined (though not likely)

### Disclaimer
This implementation is under heavy development and this version is only for testing purposes at this time. The methods utilized through this service is subject to change with the release of the tx fee model ahead of mainnet release and can/will be re-evaluated ahead of that time.

### Build
You can download pre-compiled binaries and site content [here](https://github.com/Nelbert442/dM/releases/tag/v1.0.0) , or get source: 
```
go get github.com/Nelbert442/dM/...
```

### Client Service
DeroMessage-Client.go contains the client service code. This can be ran locally.

```
1) V1: Client enters deto/dero address(s) for contacts; V2: client A gets integrated address (of client B) from server side service via the normal deto address or username [V2-pending] (sent via COMMENT to integrated service addr and returned integrated via response). 
2) Client A encrypts message and sends to SC , STORE() as some random "key" (ensure it doesn't exist in SC first) and the text of the message is ~~AES-256 encrypted [future pending other methods/alternatives/compression etc.]~~ chacha20poly1305 encrypted (https://github.com/deroproject/derohe/blob/main/walletapi/cipher.go)
3) Client A sends COMMENT with variable and decrypt key (formatted: var1/mykey [hex encoded make([]byte, 32, 32)]) for specific message (random decrypt every time) to integrated addr of Client B (received from step 1)
4) Client B received tx with var / decrypt key and gets message and decrypts to be viewed.

V1 Summary: Clients share keys directly via rpc_COMMENT. Messages are encrypted with unique keys for every message (persists keys via tx look back and SC variable lookup).

V2 Summary: Server service knows no difference other than integrated addr for deto addresses (to be replaced with username or other unique id services in future), clients share keys directly. Messages are encrypted with unique keys for every message (persists keys via tx look back and SC variable lookup)
```

DeroEmail-Client usage and help output below (heavy development and will be modified in future iterations)
```
DeroMessage-Client
DERO Message Service (client): End to End encryption where only the involved parties can ever encode/decode the contents

Usage:
  DeroMessage-Client [options]
  DeroMessage-Client -h | --help

Options:
  -h --help     Show this screen.
  --rpc-server-address=<127.0.0.1:40403>	connect to service (client) wallet
  --api-port=<8224>	API (non-SSL) will be enabled at the defined port (or defaulted to 127.0.0.1:8224)
  --ssl-api-port=<8225>	if defined, API (SSL) will be enabled at the defined port. apifullchain.cer && apicert.key in the same dir is required
  --frontend-port=<8080>	if defined, frontend (non-SSL) will be enabled
  --ssl-frontend-port=<8181>	if defined, frontend (SSL) will be enabled. fefullchain.cer && fecert.key in the same dir is required
```

### Backend DB for Server/Client Service (graviton)
In usual form with DERO projects I have taken on recently, I leverage [Graviton](https://github.com/deroproject/graviton) for the backend DB store.

![dM Console Output](assets/commandLineOutputExample.PNG?raw=true)

### Frontend
The frontend is hosted by default at localhost:8080 . The site contents are within the /site/ folder . SSL is possible, however most likely leaving that for V2 (welcome to read through the code and add the necessary cert files). You are able to pass params such as --frontend-port=9090 to switch up which port the frontend listens on, in the event you have other conflicting applications.

![dM Send Message](assets/sendMessage.PNG?raw=true)
![dM Inbox](assets/inboxMessages.PNG?raw=true)

### API
The API serves up the rawtext, decryption keys, SC variables etc. necessary. By default this is locally bound (127.0.0.1/localhost) and not externally bound, so all data stays internal and is only accessible locally. By default this is hosted at localhost:8224 , but is able to be changed via --api-port=8334 for example. SSL is possible, utilize the details within code for the certificate file names (stored in the root where the exe file is), but a V2 implementation most likely for a better SSL experience is possible.