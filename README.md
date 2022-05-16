# dM (DERO Message)
dM is a 100% on-chain solution to encrypted messaging. It leverages DERO's native smart contract language DVM-Basic in order to store encrypted strings on the blockchain and a unique identifier which is then sent via homomorphically encrypted transaction to your receiver(s) along with the decryption key. Every message is uniquely encrypted and no identifiable information is ever leaked with respect to who sent the tx nor who stored the value on the smart contract. We can ensure privacy while interacting with the smart contract because the 'InputStr' function does not utilize a SIGNER() function and thus we can send a tx with ringsize > 2 in order to further add deniability.

### Disclaimer
dM is under heavy development. There are certain capabilities that are not yet implemented such as gas/tx fee estimation etc. I strongly suggest trying this out on a DERO testnet (public or local) to get a feel for the functionality as well as the fees to expect. Operate at your own risk. I am not responsible for large tx fees as the dApp WILL send these txs without prompting you first regarding the fees associated with your messages to be sent (at this time).

### Build
You can download pre-compiled binaries and site content [here](https://github.com/Nelbert442/dM/releases/tag/v1.1.0) , or get source: 
```
go get github.com/Nelbert442/dM/...
```

### Client Service
DeroMessage-Client.go contains the client service code. This can be ran locally or remotely, however strong suggestion is to run it locally (maximum privacy).

```
1) Client enters deto/dero address(s) for contacts
a) FUTURE: client can enter in registered names from the builtin registration smart contract.

2) Client A encrypts message and sends to SC , STORE() as some random "key" (ensure it doesn't exist in SC first) and the text of the message is ~~AES-256 encrypted [future pending other methods/alternatives/compression etc.]~~ chacha20poly1305 encrypted (https://github.com/deroproject/derohe/blob/main/walletapi/cipher.go)

3) Client A sends COMMENT with variable and decrypt key (formatted: var1/mykey [hex encoded make([]byte, 32, 32)]) for specific message (random decrypt every time) to addr of Client B (received from step 1)

4) Client B received tx with var / decrypt key and gets message from SC/chain and decrypts to be viewed.

Summary: Clients share keys directly via rpc_COMMENT which is encrypted homomorphically. Messages are encrypted with unique keys for every message (persists keys via tx look back and SC variable lookup).
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
  --rpc-server-address=<127.0.0.1:10103>	connect to service (client) wallet
  --daemon-rpc-address=<127.0.0.1:10102>	connect to daemon
  --api-port=<8224>	API (non-SSL) will be enabled at the defined port (or defaulted to 127.0.0.1:8224)
  --ssl-api-port=<8225>	if defined, API (SSL) will be enabled at the defined port. apifullchain.cer && apicert.key in the same dir is required
  --frontend-port=<8080>	if defined, frontend (non-SSL) will be enabled
  --ssl-frontend-port=<8181>	if defined, frontend (SSL) will be enabled. fefullchain.cer && fecert.key in the same dir is required
  --scid=<805ade9294d01a8c9892c73dc7ddba012eaa0d917348f9b317b706131c82a2d5>		if defined, code will leverage custom SCID for store (this MUST be similar to this repo's .bas contract, else very similar methods .. or else you will get errs)`
```

### Frontend
The frontend is hosted by default at localhost:8080 . The site contents are within the /site/ folder . SSL is possible, and you will need to specify the port as well as the fullchain.cer and cert.key files within the same directory as the executable. You are able to pass params such as --frontend-port=9090 to switch up which port the frontend listens on, in the event you have other conflicting applications.

SSL File Naming (can change within code to match yours and recompile if you choose):
fefullchain.cer
fecert.key

![dM Send Message](assets/sendMessage.PNG?raw=true)
![dM Inbox](assets/inboxMessages.PNG?raw=true)

### API
The API serves up the rawtext, decryption keys, SC variables etc. necessary. By default this is locally bound (127.0.0.1/localhost) and not externally bound, so all data stays internal and is only accessible locally. By default this is hosted at localhost:8224 , but is able to be changed via --api-port=8334 for example. SSL is possible, utilize the details within code for the certificate file names (stored in the root where the exe file is).

SSL File Naming (can change within code to match yours and recompile if you choose):
apifullchain.cer
apicert.key

### Backend DB for Server/Client Service (graviton)
In usual form with DERO projects I have taken on recently, I leverage [Graviton](https://github.com/deroproject/graviton) for the backend DB store.

![dM Console Output](assets/commandLineOutputExample.PNG?raw=true)