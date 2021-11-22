package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/graviton"
	"github.com/docopt/docopt-go"
	"github.com/gorilla/mux"

	"github.com/ybbus/jsonrpc"
)

type GravitonStore struct {
	DB            *graviton.Store
	DBFolder      string
	DBPath        string
	DBTree        string
	migrating     int
	DBMaxSnapshot uint64
	DBMigrateWait time.Duration
	Writing       int
}

type TreeKV struct {
	k []byte
	v []byte
}

type TXDetails struct {
	TimeStamp  int64
	Key        []byte
	ScValue    string
	Txid       string
	RawMessage string
	Sender     string
}

type SendDetails struct {
	TimeStamp int64
	Recipient string
	ScValue   string
	Key       []byte
}

type SentMessages struct {
	SentTXs []*SendDetails
}

type Messages struct {
	MessageTXs []*TXDetails
}

type ApiServer struct {
	stats             atomic.Value
	statsIntv         string
	donationAddress   string
	faucetRainAddress string
}

type Website struct {
	Enabled  bool
	Port     string
	SSL      bool
	SSLPort  string
	CertFile string
	KeyFile  string
}

type SendMessageEntry struct {
	Username    string `json:"contactname"`
	Messagetext string `json:"messagetext"`
	Messagetags string `json:"messagetags"`
}

// Mainnet TODO: Adding params for default vals like website ssl, default multiplier, default function, etc.
var command_line string = `DeroMessage-Client
DERO Message Service (client): End to End encryption where only the involved parties can ever encode/decode the contents

Usage:
  DeroMessage-Client [options]
  DeroMessage-Client -h | --help

Options:
  -h --help     Show this screen.
  --rpc-server-address=<127.0.0.1:40403>	connect to service (client) wallet
  --daemon-rpc-address=<127.0.0.1:40402>	connect to daemon
  --api-port=<8224>	API (non-SSL) will be enabled at the defined port (or defaulted to 127.0.0.1:8224)
  --ssl-api-port=<8225>	if defined, API (SSL) will be enabled at the defined port. apifullchain.cer && apicert.key in the same dir is required
  --frontend-port=<8080>	if defined, frontend (non-SSL) will be enabled
  --ssl-frontend-port=<8181>	if defined, frontend (SSL) will be enabled. fefullchain.cer && fecert.key in the same dir is required
  --scid=<32793ea5dc8ccbfd9c9bdf47135ad75556c8a9e0fd7beeb4eb8e737a60540f8a>		if defined, code will leverage custom SCID for store (this MUST be similar to this repo's .bas contract, else very similar methods or else you will get errs)`

var api_nonssl_addr string
var api_ssl_addr string
var api_use_ssl bool

var prevTH int64
var writeWait time.Duration
var thAddition int64

const API_CERTFILE = "apifullchain.cer"
const API_KEYFILE = "apicert.key"

// Some constant vars, in future Mainnet TODO: implementation these will be properly defined in config/other .go integrations
const PLUGIN_NAME = "Dero_Message"

const DEST_PORT = uint64(0x3624573784230000)

// currently the interpreter seems to have a glitch if this gets initialized within the code
// see limitations github.com/traefik/yaegi
var messageSend = rpc.Arguments{
	{rpc.RPC_DESTINATION_PORT, rpc.DataUint64, DEST_PORT},
	{rpc.RPC_SOURCE_PORT, rpc.DataUint64, DEST_PORT},
	{rpc.RPC_COMMENT, rpc.DataString, ""},
}

var walletRPCClient jsonrpc.RPCClient
var derodRPCClient jsonrpc.RPCClient
var scid string
var serviceAddress string

var Graviton_backend *GravitonStore = &GravitonStore{}
var API *ApiServer = &ApiServer{
	statsIntv: "10s",
}

// Main function that provisions persistent graviton store, gets listening wallet addr & service listeners spun up and calls looped function to keep service alive
func main() {
	var err error
	var walletEndpoint string
	var daemonEndpoint string

	writeWait, _ = time.ParseDuration("5s")
	thAddition = 1

	var arguments map[string]interface{}

	if err != nil {
		log.Fatalf("[Main] Error while parsing arguments err: %s\n", err)
	}

	arguments, err = docopt.Parse(command_line, nil, true, "DERO Message Client : work in progress", false)
	_ = arguments

	log.Printf("[Main] DERO Message Service (client) :  This is under heavy development, use it for testing/evaluations purpose only\n")

	// Set variables from arguments
	walletEndpoint = "127.0.0.1:40403"
	if arguments["--rpc-server-address"] != nil {
		walletEndpoint = arguments["--rpc-server-address"].(string)
	}

	log.Printf("[Main] Using wallet RPC endpoint %s\n", walletEndpoint)

	// create wallet client
	walletRPCClient = jsonrpc.NewClient("http://" + walletEndpoint + "/json_rpc")

	// create daemon client
	daemonEndpoint = "127.0.0.1:40402"
	if arguments["--daemon-rpc-address"] != nil {
		daemonEndpoint = arguments["--daemon-rpc-address"].(string)
	}

	log.Printf("[Main] Using daemon RPC endpoint %s\n", daemonEndpoint)

	derodRPCClient = jsonrpc.NewClient("http://" + daemonEndpoint + "/json_rpc")

	// Set SCID - default to repo's default. No matter the SCID.. information is not leaked since the client handles key traversal & encrypt/decrypt messages.
	scid = "32793ea5dc8ccbfd9c9bdf47135ad75556c8a9e0fd7beeb4eb8e737a60540f8a"
	if arguments["--scid"] != nil {
		scid = arguments["--scid"].(string)
	}

	// TODO: Cleanup implementation of this a bit.. need cleaner and more defined param vs what is setup by default (api by default, perhaps local web by default as well in this implementation)
	api_use_ssl = false
	api_nonssl_addr = "127.0.0.1:8224"
	if arguments["--api-port"] != nil {
		api_nonssl_addr = "127.0.0.1:" + arguments["--api-port"].(string)
		if api_nonssl_addr != "127.0.0.1:8224" {
			log.Printf("[Main] You are using a different non-ssl API address than default, don't forget to update config.js file for the local site!")
		}
	}

	api_ssl_addr = "127.0.0.1:8225"
	if arguments["--ssl-api-port"] != nil {
		api_use_ssl = true
		api_ssl_addr = "127.0.0.1:" + arguments["--ssl-api-port"].(string)
		log.Printf("[Main] You are using a ssl API address which is not the default site config, don't forget to update config.js file for the local site!")
	}

	var frontend_port, ssl_frontend_port string
	var frontend_ssl_enabled bool

	frontend_port = "8080"
	if arguments["--frontend-port"] != nil {
		frontend_port = arguments["--frontend-port"].(string)
	}

	if arguments["--ssl-frontend-port"] != nil {
		ssl_frontend_port = arguments["--ssl-frontend-port"].(string)
		frontend_ssl_enabled = true
	}

	// Define website params
	var web *Website = &Website{
		Enabled:  true,
		Port:     frontend_port,
		SSL:      frontend_ssl_enabled,
		SSLPort:  ssl_frontend_port,
		CertFile: "fefullchain.cer",
		KeyFile:  "fecert.key",
	}

	// Test rpc-server connection to ensure wallet connectivity, exit out if not
	var addr *rpc.Address
	var addr_result rpc.GetAddress_Result
	err = walletRPCClient.CallFor(&addr_result, "GetAddress")
	if err != nil || addr_result.Address == "" {
		log.Printf("[Main] Could not obtain address from wallet (http://%s/json_rpc) err %s\n", walletEndpoint, err)
		return
	}

	if addr, err = rpc.NewAddress(addr_result.Address); err != nil {
		log.Printf("[Main] address could not be parsed: addr:%s err:%s\n", addr_result.Address, err)
		return
	}

	serviceAddress = addr_result.Address

	shasum := fmt.Sprintf("%x", sha1.Sum([]byte(addr.String())))

	db_folder := fmt.Sprintf("%s_%s", PLUGIN_NAME, shasum)

	Graviton_backend.NewGravDB("deromessage", db_folder, "25ms", 5000)

	log.Printf("[Main] Persistant store for processed txids created in '%s'\n", db_folder)

	go api_process(API) // start api process / listener
	if web.Enabled {
		go web_process(web) // start web process / listener
	}

	// Start listening/processing received messages
	processReceivedMessages()
}

// ---- Message functions ---- //
func processSendingMessages(varname string, plaintext string, destinationAddresses string, messagetags string) string {
	// Version 2 TODO: messagetags are leveraged for replying/forwarding messages

	// Check if the variable already exists, if it does exit out (FOR NOW), possibly add --overwrite option or something for data recycling at a later time
	log.Printf("[processSendingMessages] Checking '%v' to see if it is already used in SC.", varname)
	varTap := checkUserKeyResults(varname)
	resCheck := strings.Split(varTap, ":")

	if resCheck[0] != "NOT AVAILABLE err" {
		log.Printf("[processSendingMessages] ERR: There is already encrypted context stored at defined variable '%v'. Please use a different variable name", varname)
		return fmt.Sprintf("ERR: There is already encrypted context stored at defined variable '%v'. Please try re-sending your message.", varname)
	} else {
		log.Printf("[processSendingMessages] Var '%v' is not already defined in SC, proceeding.", varname)
	}

	if destinationAddresses == "" {
		log.Printf("[processSendingMessages] ERR: No destination defined. Not sending message.")
		return fmt.Sprintf("ERR: No destination defined.")
	}

	if plaintext == "" {
		log.Printf("[processSendingMessages] ERR: No message text entered. Not sending message.")
		return fmt.Sprintf("ERR: No message text entered.")
	}

	// Randomly generate and Encrypt the user password
	passwordKey := make([]byte, 32, 32)
	_, err := rand.Read(passwordKey)
	if err != nil {
		// TODO: Better err handling on pwd key generation (if required)
		log.Printf("[processSendingMessages] Err randomly reading passwordkey")
	}

	// SC Var does not exist, continue on to opening the message and encrypting --> sending.
	log.Printf("[processSendingMessages] original string (len: %v): \n%v", len(plaintext), plaintext)

	err = encryptAndSend(passwordKey, plaintext, varname)
	if err != nil {
		log.Printf("[processSendingMessages] Err encrypting and sending: \n%v", err)
	}

	var messageSend = rpc.Arguments{
		{rpc.RPC_DESTINATION_PORT, rpc.DataUint64, uint64(0)},
		{rpc.RPC_SOURCE_PORT, rpc.DataUint64, DEST_PORT},
		{rpc.RPC_COMMENT, rpc.DataString, ""},
	}

	txReply := fmt.Sprintf("%v/%v", varname, hex.EncodeToString(passwordKey))
	messageSend[2].Value = txReply

	var transfers []rpc.Transfer

	addressSplit := strings.Split(destinationAddresses, ";")
	if len(addressSplit) > 1 {
		for _, v := range addressSplit {
			trimAddress := strings.Replace(v, " ", "", -1)

			// Validate the address
			if _, err := rpc.NewAddress(trimAddress); err != nil {
				log.Printf("[processSendingMessages] address could not be parsed: addr:%s err:%s\n", trimAddress, err)
				return fmt.Sprintf("ERR: address could not be parsed - %v", err)
			}

			// Check serviceAddress to ensure none of the contacts are the same
			if trimAddress == serviceAddress {
				log.Printf("[processSendingMessages] destination address is the same as the source. Please check your 'TO' field to ensure you aren't sending to yourself.")
				return fmt.Sprintf("ERR: destination address is the same as the source. Please check your 'TO' field to ensure you aren't sending to yourself.")
			}

			transfers = append(transfers, rpc.Transfer{Destination: trimAddress, Amount: uint64(1), Payload_RPC: messageSend})
		}
	} else {
		trimAddress := strings.Replace(destinationAddresses, " ", "", -1)

		// Validate the address
		if _, err := rpc.NewAddress(trimAddress); err != nil {
			log.Printf("[processSendingMessages] address could not be parsed: addr:%s err:%s\n", trimAddress, err)
			return fmt.Sprintf("ERR: address could not be parsed - %v", err)
		}

		// Check serviceAddress to ensure none of the contacts are the same
		if trimAddress == serviceAddress {
			log.Printf("[processSendingMessages] destination address is the same as the source. Please check your 'TO' field to ensure you aren't sending to yourself.")
			return fmt.Sprintf("ERR: destination address is the same as the source. Please check your 'TO' field to ensure you aren't sending to yourself.")
		}

		transfers = append(transfers, rpc.Transfer{Destination: trimAddress, Amount: uint64(1), Payload_RPC: messageSend})
	}

	log.Printf("[processSendingMessages] Sending transfers tx...")
	txSendRes := sendTx(transfers, varname, passwordKey)

	var results string

	if txSendRes == "" {
		results = "Successfully sent message!"
	} else {
		results = txSendRes
	}

	return results
}

func processReceivedMessages() {

	for { // currently we traverse entire history

		time.Sleep(time.Second)

		var transfers rpc.Get_Transfers_Result
		err := walletRPCClient.CallFor(&transfers, "GetTransfers", rpc.Get_Transfers_Params{In: true, SourcePort: DEST_PORT, DestinationPort: DEST_PORT})
		if err != nil {
			log.Printf("[processReceivedMessages] Could not obtain gettransfers from wallet err %s\n", err)
			continue
		}

		for _, e := range transfers.Entries {

			if e.Coinbase || !e.Incoming { // skip coinbase or outgoing, self generated transactions
				continue
			}

			// check whether the entry has been processed before, if yes skip it
			var already_processed bool

			// Mainnet TODO: Make the function names dynamic of sorts.. or perhaps trust the service will "fix" all and some other comparison can be leveraged
			var varName string
			var passwordString string
			if e.Payload_RPC.Has(rpc.RPC_COMMENT, rpc.DataString) {
				payloadComment := e.Payload_RPC.Value(rpc.RPC_COMMENT, rpc.DataString).(string)

				multFunc := strings.Split(payloadComment, "/")
				if len(multFunc) > 1 {
					varName = multFunc[0]

					passwordString = multFunc[1]
				}
			} else {
				log.Printf("[processReceivedMessages] Waiting for tx...")
				time.Sleep(10 * time.Second)
				continue
			}

			passwordKey, err := hex.DecodeString(passwordString)

			if err != nil {
				log.Printf("[processReceivedMessages] Error decoding decryptionkey for SC var %v . Will circle back around and try again", varName) // Mainnet TODO: Fix for proper error handling such as exclude tx or note message to be "unopenable" or something
				continue
			}

			// Get txDetail [sender+txid] from graviton store, if received it is already processed else continue
			txDetails := Graviton_backend.GetTXs()

			// Loop through TXs to see if txid exists
			for _, v := range txDetails {
				if txDetails != nil {
					if v != nil {
						if v.ScValue == varName && string(v.Key) == string(passwordKey) {
							already_processed = true
						}
					}
				}
			}

			if already_processed { // if already processed skip it
				continue
			}

			// Logging only, remove later
			log.Printf("[processReceivedMessages] varName: %v, passwordString: %v", varName, passwordString)

			// check whether this service should handle the transfer
			if !e.Payload_RPC.Has(rpc.RPC_SOURCE_PORT, rpc.DataUint64) ||
				DEST_PORT != e.Payload_RPC.Value(rpc.RPC_SOURCE_PORT, rpc.DataUint64).(uint64) {

				log.Printf("[processReceivedMessages] Tx doesn't meet filter requirements...")
				time.Sleep(10 * time.Second)
				continue
			}

			var txTime int64
			txTime = (e.Time.UnixNano() / int64(time.Millisecond)) / 1000
			decryptedText := receiveAndDecrypt(passwordKey, varName, e.TXID, e.Sender, txTime)
			if decryptedText != "" {
				log.Printf("[processReceivedMessages] DecryptedText: \n%v", decryptedText)
			} else {
				log.Printf("[processReceivedMessages] Unable to get decrypted text yet, will circle back..")
			}
		}
	}
}

func encryptAndSend(key []byte, plaintext string, varname string) error {
	/* Encrypt */
	// AES-256 Encryption .. replaced w/ walletapi.EncryptWithKey ("golang.org/x/crypto/chacha20poly1305")
	//ciphertext := encrypt(key, string(plaintext))
	//log.Printf("cipherText: \n%v", ciphertext)

	/* Using deroproject cipher.go encryption functions
	encResult, err := walletapi.EncryptWithKey(key, []byte(plaintext))
	if err != nil {
		log.Printf("[encryptAndSend] Err encrypting message: %v", err)
		return err
	}
	*/

	/*
		Using chacha20poly1305 NewX - https://golang.org/pkg/vendor/golang.org/x/crypto/chacha20poly1305/

		XChaCha20-Poly1305 is a ChaCha20-Poly1305 variant that takes a longer nonce, suitable to be generated randomly without risk of collisions.
		It should be preferred when nonce uniqueness cannot be trivially ensured, or whenever nonces are randomly generated.
	*/
	nonce := make([]byte, chacha20poly1305.NonceSizeX, chacha20poly1305.NonceSizeX)
	cipher, err := chacha20poly1305.NewX(key)
	if err != nil {
		log.Printf("[encryptAndSend] Err generating chacha20poly1305 cipher: %v", err)
		return err
	}

	_, err = rand.Read(nonce)
	if err != nil {
		log.Printf("[encryptAndSend] Err randomly reading nonce: %v", err)
		return err
	}

	Data := []byte(plaintext)

	Data = cipher.Seal(Data[:0], nonce, Data, nil)

	encResult := append(Data, nonce...)

	log.Printf("[encryptAndSend] Encrypted text: %v", encResult)
	ciphertext := hex.EncodeToString(encResult)
	log.Printf("[encryptAndSend] Ciphertext: %v", ciphertext)

	// Future TODO: If compression is required/used, define it here

	/* Call SC - this is to input data into a SC that just takes a simple string and stores it to a simple var [single TX store compressed & encoded txt to be pulled from later]*/
	//var scstr string
	var scstr rpc.Transfer_Result
	var rpcArgs = rpc.Arguments{}
	rpcArgs = append(rpcArgs, rpc.Argument{Name: "entrypoint", DataType: "S", Value: "InputStr"})
	rpcArgs = append(rpcArgs, rpc.Argument{Name: "input", DataType: "S", Value: string(ciphertext)})
	rpcArgs = append(rpcArgs, rpc.Argument{Name: "varname", DataType: "S", Value: varname})
	scparams := rpc.SC_Invoke_Params{SC_ID: scid, Ringsize: 2, SC_RPC: rpcArgs}
	if prevTH != 0 {
		for {
			var info rpc.GetInfo_Result
			err = derodRPCClient.CallFor(&info, "get_info")
			if err != nil {
				return err
			}

			targetTH := prevTH + thAddition

			if targetTH <= info.TopoHeight {
				prevTH = info.TopoHeight
				break
			} else {
				log.Printf("[sendTX] Waiting until topoheights line up to send next TX [last: %v / curr: %v]", info.TopoHeight, targetTH)
				time.Sleep(writeWait)
			}
		}
	} else {
		var info rpc.GetInfo_Result
		err = derodRPCClient.CallFor(&info, "get_info")
		if err != nil {
			return err
		}

		prevTH = info.TopoHeight
	}
	err = walletRPCClient.CallFor(&scstr, "scinvoke", scparams)
	if err != nil {
		log.Printf("[encryptAndSend] sending SC tx err %s\n", err)
		return err
	} else {
		log.Printf("[encryptAndSent] Sent SC tx successfully - txid: %v", scstr.TXID)
	}

	return nil
}

func receiveAndDecrypt(key []byte, scVarName string, txid string, sender string, txtime int64) string {
	//Receive from SC and decode results, comment out until I put in functions etc..
	var results string
	for {
		results = checkUserKeyResults(scVarName)

		resCheck := strings.Split(results, ":")

		if resCheck[0] == "NOT AVAILABLE err" {
			log.Printf("[receiveAndDecrypt] No key found yet for %v, will circle back...", scVarName)
			time.Sleep(10 * time.Second)
			return ""
		} else {
			log.Printf("[receiveAndDecrypt] results from SC found for %v.. continuing", scVarName)
			break
		}
	}
	// TODO: Handle err (no key/leaf avail)

	// Future TODO: If compression is required/used, define decompression it here

	// Decrypt data
	//decryptedText := decrypt(key, results) // AES-256 Decryption .. replaced w/ walletapi.DecryptWithKey ("golang.org/x/crypto/chacha20poly1305")
	// We have to decode string twice, because sc store encodes it again after original
	firstResultByte, err := hex.DecodeString(results)
	if err != nil {
		log.Printf("[receiveAndDecrypt] Err decoding stored SC hex encoded string first time around..")
	}
	firstResultToString := string(firstResultByte)
	resultByte, err := hex.DecodeString(firstResultToString)
	if err != nil {
		log.Printf("[receiveAndDecrypt] Err decoding stored SC hex encoded string.")
		return ""
	}

	/* Using deroproject cipher.go encryption functions
	decResult, err := walletapi.DecryptWithKey(key, resultByte)
	if err != nil {
		log.Printf("[receiveAndDecrypt] Err decrypting message: %v", err)
		return ""
	}
	*/

	/*
		Using chacha20poly1305 NewX - https://golang.org/pkg/vendor/golang.org/x/crypto/chacha20poly1305/

		XChaCha20-Poly1305 is a ChaCha20-Poly1305 variant that takes a longer nonce, suitable to be generated randomly without risk of collisions.
		It should be preferred when nonce uniqueness cannot be trivially ensured, or whenever nonces are randomly generated.
	*/
	var decResult []byte
	data_without_nonce := resultByte[0 : len(resultByte)-chacha20poly1305.NonceSizeX]

	nonce := resultByte[len(resultByte)-chacha20poly1305.NonceSizeX:]

	cipher, err := chacha20poly1305.NewX(key)
	if err != nil {
		log.Printf("[receiveAndDecrypt] Err decrypting key: %v", err)
		return ""
	}

	decResult, err = cipher.Open(decResult[:0], nonce, data_without_nonce, nil)
	if err != nil {
		log.Printf("[receiveAndDecrypt] Err decrypting message: %v", err)
		return ""
	}

	decryptedText := string(decResult)

	// Store new txdetails in graviton store
	newTxDetails := &TXDetails{ScValue: scVarName, Key: key, RawMessage: decryptedText, Txid: txid, Sender: sender, TimeStamp: txtime}
	err = Graviton_backend.StoreTX(newTxDetails)

	if err != nil {
		log.Printf("[receiveAndDecrypt] err updating db to err %s\n", err)
	} else {
		log.Printf("[receiveAndDecrypt] TX Received and stored")
	}

	return decryptedText
}

func checkUserKeyResults(userKey string) string {
	// Grab userKey value from SC
	var scstr *rpc.GetSC_Result
	var strings []string
	strings = append(strings, userKey)
	getSC := rpc.GetSC_Params{SCID: scid, Code: false, KeysString: strings}
	err := derodRPCClient.CallFor(&scstr, "getsc", getSC)
	if err != nil {
		log.Printf("[checkUserKeyResults] getting SC tx err %s\n", err)
		return ""
	}

	log.Printf("[checkUserKeyResults] Returned string - %v", scstr)

	if len(scstr.ValuesString) > 1 {
		log.Printf("[checkUserKeyResults] more than 1 value returned for '%v'. Will be returning slot 0, here are all of them: %v\n", userKey, scstr.ValuesString)
	}

	return scstr.ValuesString[0]
}

// encrypt string to base64 crypto using AES - https://gist.github.com/manishtpatel/8222606
func encrypt(key []byte, text string) string {
	plaintext := []byte(text)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// convert to base64
	return base64.URLEncoding.EncodeToString(ciphertext)
}

// decrypt from base64 to decrypted string - https://gist.github.com/manishtpatel/8222606
func decrypt(key []byte, cryptoText string) string {
	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext)
}

func sendTx(transfers []rpc.Transfer, scvalue string, key []byte) string {
	// sender of ping now becomes destination
	//var str string
	var str rpc.Transfer_Result
	tparams := rpc.Transfer_Params{Transfers: transfers}

	if prevTH != 0 {
		for {
			var info rpc.GetInfo_Result
			err := derodRPCClient.CallFor(&info, "get_info")
			if err != nil {
				return fmt.Sprintf("ERR: %v", err)
			}

			targetTH := prevTH + thAddition

			if targetTH <= info.TopoHeight {
				prevTH = info.TopoHeight
				break
			} else {
				log.Printf("[sendTX] Waiting until topoheights line up to send next TX [last: %v / curr: %v]", info.TopoHeight, targetTH)
				time.Sleep(writeWait)
			}
		}
	} else {
		var info rpc.GetInfo_Result
		err := derodRPCClient.CallFor(&info, "get_info")
		if err != nil {
			return fmt.Sprintf("ERR: %v", err)
		}

		prevTH = info.TopoHeight
	}

	err := walletRPCClient.CallFor(&str, "Transfer", tparams)
	if err != nil {
		log.Printf("[sendTx] err: %v", err)
		return fmt.Sprintf("ERR: %v", err)
	} else {
		log.Printf("[sendTx] Tx sent successfully - txid: %v", str.TXID)
	}

	for _, v := range transfers {
		if transfers != nil {
			// Store new txdetails in graviton store
			timestamp := (time.Now().UnixNano() / int64(time.Millisecond)) / 1000
			newTxDetails := &SendDetails{Recipient: v.Destination, ScValue: scvalue, Key: key, TimeStamp: timestamp}
			err := Graviton_backend.StoreSentTX(newTxDetails)

			if err != nil {
				log.Printf("[sendTx] err updating db to err %s\n", err)
			} else {
				log.Printf("[sendTx] TX Sent and stored")
			}
		}
	}

	return ""
}

// ---- End Message functions ---- //

// ---- Graviton/Backend functions ---- //
// Mainnet TODO: Proper graviton/backend .go file(s)
// Builds new Graviton DB based on input from main()
func (g *GravitonStore) NewGravDB(poolhost, dbFolder, dbmigratewait string, dbmaxsnapshot uint64) {
	current_path, err := os.Getwd()
	if err != nil {
		log.Printf("%v", err)
	}

	g.DBMigrateWait, _ = time.ParseDuration(dbmigratewait)

	g.DBMaxSnapshot = dbmaxsnapshot

	g.DBFolder = dbFolder

	g.DBPath = filepath.Join(current_path, dbFolder)

	g.DB, err = graviton.NewDiskStore(g.DBPath)
	if err != nil {
		log.Fatalf("[NewGravDB] Could not create db store: %v", err)
	}

	g.DBTree = poolhost
}

// Swaps the store pointer from existing to new after copying latest snapshot to new DB - fast as cursor + disk writes allow [possible other alternatives such as mem store for some of these interwoven, testing needed]
func (g *GravitonStore) SwapGravDB(poolhost, dbFolder string) {
	// Use g.migrating as a simple 'mutex' of sorts to lock other read/write functions out of doing anything with DB until this function has completed.
	g.migrating = 1

	// Rename existing bak to bak2, then goroutine to cleanup so process doesn't wait for old db cleanup time
	var bakFolder string = dbFolder + "_bak"
	var bak2Folder string = dbFolder + "_bak2"
	log.Printf("[SwapGravDB] Renaming directory %v to %v", bakFolder, bak2Folder)
	os.Rename(bakFolder, bak2Folder)
	log.Printf("[SwapGravDB] Removing directory %v", bak2Folder)
	go os.RemoveAll(bak2Folder)

	// Get existing store values, defer close of original, and get store values for new DB to write to
	store := g.DB
	ss, _ := store.LoadSnapshot(0)

	tree, _ := ss.GetTree(g.DBTree)
	log.Printf("[SwapGravDB] SS: %v", ss.GetVersion())

	c := tree.Cursor()
	log.Printf("[SwapGravDB] Getting k/v pairs")
	// Duplicate the LATEST (snapshot 0) to the new DB, this starts the DB over again, but still retaining X number of old DBs for version in future use cases. Here we get the vals before swapping to new db in mem
	var treeKV []*TreeKV // Just k & v which are of type []byte
	for k, v, err := c.First(); err == nil; k, v, err = c.Next() {
		temp := &TreeKV{k, v}
		treeKV = append(treeKV, temp)
	}
	log.Printf("[SwapGravDB] Closing store")
	store.Close()

	// Backup last set of g.DBMaxSnapshot snapshots, can offload elsewhere or make this process as X many times as you want to backup.
	var oldFolder string
	oldFolder = g.DBPath
	log.Printf("[SwapGravDB] Renaming directory %v to %v", oldFolder, bakFolder)
	os.Rename(oldFolder, bakFolder)

	log.Printf("[SwapGravDB] Creating new disk store")
	g.DB, _ = graviton.NewDiskStore(g.DBPath)

	// Take vals from previous DB store that were put into treeKV struct (array of), and commit to new DB after putting all k/v pairs back
	store = g.DB
	ss, _ = store.LoadSnapshot(0)
	tree, _ = ss.GetTree(g.DBTree)

	log.Printf("[SwapGravDB] Putting k/v pairs into tree...")
	for _, val := range treeKV {
		tree.Put(val.k, val.v)
	}
	log.Printf("[SwapGravDB] Committing k/v pairs to tree")
	_, cerr := graviton.Commit(tree)
	if cerr != nil {
		log.Printf("[SwapGravDB] ERROR: %v", cerr)
	}
	log.Printf("[SwapGravDB] Migration to new DB is done.")
	g.migrating = 0
}

// Gets TX details
func (g *GravitonStore) GetTXs() []*TXDetails {
	store := g.DB
	ss, _ := store.LoadSnapshot(0) // load most recent snapshot

	// Swap DB at g.DBMaxSnapshot+ commits. Check for g.migrating, if so sleep for g.DBMigrateWait ms
	for g.migrating == 1 {
		log.Printf("[GetTXs] G is migrating... sleeping for %v...", g.DBMigrateWait)
		time.Sleep(g.DBMigrateWait)
		store = g.DB
		ss, _ = store.LoadSnapshot(0) // load most recent snapshot
	}
	if ss.GetVersion() >= g.DBMaxSnapshot {
		Graviton_backend.SwapGravDB(Graviton_backend.DBTree, Graviton_backend.DBFolder)

		store = g.DB
		ss, _ = store.LoadSnapshot(0) // load most recent snapshot
	}

	tree, _ := ss.GetTree(g.DBTree) // use or create tree named by poolhost in config
	key := "messages"
	var reply *Messages

	v, _ := tree.Get([]byte(key))
	if v != nil {
		_ = json.Unmarshal(v, &reply)
		return reply.MessageTXs
	}

	return nil
}

// Stores TX details
func (g *GravitonStore) StoreTX(txDetails *TXDetails) error {
	store := g.DB
	ss, _ := store.LoadSnapshot(0) // load most recent snapshot

	// Swap DB at g.DBMaxSnapshot+ commits. Check for g.migrating, if so sleep for g.DBMigrateWait ms
	for g.migrating == 1 {
		log.Printf("[StoreTX] G is migrating... sleeping for %v...", g.DBMigrateWait)
		time.Sleep(g.DBMigrateWait)
		store = g.DB
		ss, _ = store.LoadSnapshot(0) // load most recent snapshot
	}
	if ss.GetVersion() >= g.DBMaxSnapshot {
		Graviton_backend.SwapGravDB(Graviton_backend.DBTree, Graviton_backend.DBFolder)

		store = g.DB
		ss, _ = store.LoadSnapshot(0) // load most recent snapshot
	}

	tree, _ := ss.GetTree(g.DBTree)
	key := "messages"

	currMessages, err := tree.Get([]byte(key))
	var messages *Messages

	var newMessages []byte

	if err != nil {
		// Returns key not found if != nil, or other err, but assuming keynotfound/leafnotfound
		var txDetailsArr []*TXDetails
		txDetailsArr = append(txDetailsArr, txDetails)
		messages = &Messages{MessageTXs: txDetailsArr}
	} else {
		// Retrieve value and convert to BlocksFoundByHeight, so that you can manipulate and update db
		_ = json.Unmarshal(currMessages, &messages)

		messages.MessageTXs = append(messages.MessageTXs, txDetails)
	}
	newMessages, err = json.Marshal(messages)
	if err != nil {
		return fmt.Errorf("[Graviton-StoreTX] could not marshal messages info: %v", err)
	}

	log.Printf("[Graviton-StoreTX] Storing %v", txDetails)
	tree.Put([]byte(key), []byte(newMessages)) // insert a value
	_, cerr := graviton.Commit(tree)
	if cerr != nil {
		log.Printf("[Graviton-StoreTX] ERROR: %v", cerr)
	}
	return nil
}

// Gets Sent TX details
func (g *GravitonStore) GetSentTXs() []*SendDetails {
	store := g.DB
	ss, _ := store.LoadSnapshot(0) // load most recent snapshot

	// Swap DB at g.DBMaxSnapshot+ commits. Check for g.migrating, if so sleep for g.DBMigrateWait ms
	for g.migrating == 1 {
		log.Printf("[GetSentTXs] G is migrating... sleeping for %v...", g.DBMigrateWait)
		time.Sleep(g.DBMigrateWait)
		store = g.DB
		ss, _ = store.LoadSnapshot(0) // load most recent snapshot
	}
	if ss.GetVersion() >= g.DBMaxSnapshot {
		Graviton_backend.SwapGravDB(Graviton_backend.DBTree, Graviton_backend.DBFolder)

		store = g.DB
		ss, _ = store.LoadSnapshot(0) // load most recent snapshot
	}

	tree, _ := ss.GetTree(g.DBTree) // use or create tree named by poolhost in config
	key := "sentmessages"
	var reply *SentMessages

	v, _ := tree.Get([]byte(key))
	if v != nil {
		_ = json.Unmarshal(v, &reply)
		return reply.SentTXs
	}

	return nil
}

// Stores Sent TX details
func (g *GravitonStore) StoreSentTX(txDetails *SendDetails) error {
	store := g.DB
	ss, _ := store.LoadSnapshot(0) // load most recent snapshot

	// Swap DB at g.DBMaxSnapshot+ commits. Check for g.migrating, if so sleep for g.DBMigrateWait ms
	for g.migrating == 1 {
		log.Printf("[StoreSentTX] G is migrating... sleeping for %v...", g.DBMigrateWait)
		time.Sleep(g.DBMigrateWait)
		store = g.DB
		ss, _ = store.LoadSnapshot(0) // load most recent snapshot
	}
	if ss.GetVersion() >= g.DBMaxSnapshot {
		Graviton_backend.SwapGravDB(Graviton_backend.DBTree, Graviton_backend.DBFolder)

		store = g.DB
		ss, _ = store.LoadSnapshot(0) // load most recent snapshot
	}

	tree, _ := ss.GetTree(g.DBTree)
	key := "sentmessages"

	currMessages, err := tree.Get([]byte(key))
	var messages *SentMessages

	var newMessages []byte

	if err != nil {
		// Returns key not found if != nil, or other err, but assuming keynotfound/leafnotfound
		var txDetailsArr []*SendDetails
		txDetailsArr = append(txDetailsArr, txDetails)
		messages = &SentMessages{SentTXs: txDetailsArr}
	} else {
		// Retrieve value and convert to BlocksFoundByHeight, so that you can manipulate and update db
		_ = json.Unmarshal(currMessages, &messages)

		messages.SentTXs = append(messages.SentTXs, txDetails)
	}
	newMessages, err = json.Marshal(messages)
	if err != nil {
		return fmt.Errorf("[Graviton-StoreSentTX] could not marshal messages info: %v", err)
	}

	log.Printf("[Graviton-StoreSentTX] Storing %v", txDetails)
	tree.Put([]byte(key), []byte(newMessages)) // insert a value
	_, cerr := graviton.Commit(tree)
	if cerr != nil {
		log.Printf("[Graviton-StoreSentTX] ERROR: %v", cerr)
	}
	return nil
}

// ---- End Graviton/Backend functions ---- //

// ---- API functions ---- //
// Mainnet TODO: Proper api .go file(s)
// Keep api running
func api_process(cfg *ApiServer) {
	statsIntv, _ := time.ParseDuration(cfg.statsIntv)
	statsTimer := time.NewTimer(statsIntv)
	log.Printf("[API] Set stats collect interval to %v", statsIntv)

	collectStats()

	go func() {
		for {
			select {
			case <-statsTimer.C:
				collectStats()
				statsTimer.Reset(statsIntv)
			}
		}
	}()

	// If SSL is configured, due to nature of listenandserve, put HTTP in go routine then call SSL afterwards so they can run in parallel. Otherwise, run http as normal
	if api_use_ssl {
		go apiListen()
		apiListenSSL()
	} else {
		apiListen()
	}
}

// API Server listen over non-SSL
func apiListen() {
	log.Printf("[API] Starting API on %v", api_nonssl_addr)
	router := mux.NewRouter()
	// TODO: Add other apis for button clicking / running commands internal like register, send messages, receive messages (refresh? or ignore and just it is auto-refresh based on param.. will see)
	router.HandleFunc("/api/stats", statsIndex)
	router.HandleFunc("/api/sendmessage", sendMessageCall)
	router.NotFoundHandler = http.HandlerFunc(notFound)
	err := http.ListenAndServe(api_nonssl_addr, router)
	if err != nil {
		log.Fatalf("[API] Failed to start API: %v", err)
	}
}

// API Server listen over SSL
func apiListenSSL() {
	log.Printf("[API] Starting SSL API on %v", api_ssl_addr)
	routerSSL := mux.NewRouter()
	// TODO: Add other apis for button clicking / running commands internal like register, send messages, receive messages (refresh? or ignore and just it is auto-refresh based on param.. will see)
	routerSSL.HandleFunc("/api/stats", statsIndex)
	routerSSL.HandleFunc("/api/sendmessage", sendMessageCall)
	routerSSL.NotFoundHandler = http.HandlerFunc(notFound)
	err := http.ListenAndServeTLS(api_ssl_addr, API_CERTFILE, API_KEYFILE, routerSSL)
	if err != nil {
		log.Fatalf("[API] Failed to start SSL API: %v", err)
	}
}

// Serve the notfound addr
func notFound(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "application/json; charset=UTF-8")
	writer.Header().Set("Access-Control-Allow-Origin", "*")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.WriteHeader(http.StatusNotFound)
}

// API Collect Stats
func collectStats() {
	stats := make(map[string]interface{})

	// Get Inbox TX
	var apiTxs []*TXDetails
	inboxTxs := Graviton_backend.GetTXs()

	for _, v := range inboxTxs {
		if inboxTxs != nil {
			if v != nil {
				txDetail := &TXDetails{ScValue: v.ScValue, Key: v.Key, RawMessage: v.RawMessage, Txid: v.Txid, Sender: v.Sender, TimeStamp: v.TimeStamp}

				apiTxs = append(apiTxs, txDetail)
			}
		}
	}

	// Get Sent TX
	var apiSentTxs []*SendDetails

	sentTxs := Graviton_backend.GetSentTXs()

	for _, v := range sentTxs {
		if sentTxs != nil {
			if v != nil {
				txDetail := &SendDetails{TimeStamp: v.TimeStamp, Recipient: v.Recipient, ScValue: v.ScValue, Key: v.Key}

				apiSentTxs = append(apiSentTxs, txDetail)
			}
		}
	}

	// Wallet balance
	// Test rpc-server connection to ensure wallet connectivity, exit out if not
	// TODO: Is wallet balance necessary? Perhaps.. since it's small TX fees to send an message (free to receive, unless implementing validation of sender address but may not be needed)
	var balance_result *rpc.GetBalance_Result
	err := walletRPCClient.CallFor(&balance_result, "getbalance")

	if err != nil {
		log.Printf("[API-collectStats] Err getting balance from walletrpc.")
	} else {
		stats["walletBalance"] = globals.FormatMoney(balance_result.Balance)
	}

	stats["inboxMessages"] = apiTxs
	stats["sentMessages"] = apiSentTxs

	API.stats.Store(stats)
}

// API StatsIndex
func statsIndex(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "application/json; charset=UTF-8")
	writer.Header().Set("Access-Control-Allow-Origin", "*")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.WriteHeader(http.StatusOK)

	reply := make(map[string]interface{})

	stats := getStats()
	if stats != nil {
		reply["walletBalance"] = stats["walletBalance"]
		reply["inboxMessages"] = stats["inboxMessages"]
		reply["sentMessages"] = stats["sentMessages"]
	}

	err := json.NewEncoder(writer).Encode(reply)
	if err != nil {
		log.Printf("[API-statsIndex] Error serializing API response: %v", err)
	}
}

// Send message message
func sendMessageCall(writer http.ResponseWriter, req *http.Request) {
	writer.Header().Set("Content-Type", "application/json; charset=UTF-8")
	writer.Header().Set("Access-Control-Allow-Origin", "*")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.WriteHeader(http.StatusOK)

	var sendMessageInput SendMessageEntry

	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&sendMessageInput)
	if err != nil {
		log.Printf("[API-sendMessageCall] Err decoding: %v", err)
	}
	log.Printf("[API-sendMessageCall] Received message to be sent/processed: %v", sendMessageInput)

	var randKey [8]byte
	userKeyByte := randKey[0 : 8-1]
	rand.Read(randKey[:])
	copy(randKey[:], userKeyByte[:])

	varname := hex.EncodeToString(userKeyByte)

	sendResults := processSendingMessages(varname, sendMessageInput.Messagetext, sendMessageInput.Username, sendMessageInput.Messagetags)

	reply := sendResults

	err = json.NewEncoder(writer).Encode(reply)
	if err != nil {
		log.Printf("[API-sendMessageCall] Error serializing API response: %v", err)
	}
}

// API Get stats from backend
func getStats() map[string]interface{} {
	stats := API.stats.Load()
	if stats != nil {
		return stats.(map[string]interface{})
	}
	return nil
}

// ---- End API functions ---- //

// ---- Website functions ---- //
// Keep website running
func web_process(cfg *Website) {
	fileServer := http.FileServer(http.Dir("./site"))
	http.Handle("/", fileServer)

	// If SSL is enabled, configure for SSL and HTTP. Else just run HTTP
	if cfg.SSL {
		go func() {
			log.Printf("[Website] Starting website at localhost:%v\n", cfg.Port)
			addr := ":" + cfg.Port
			err := http.ListenAndServe(addr, nil)
			if err != nil {
				log.Printf("[Website] Error starting http server at localhost:%v", addr)
				log.Fatal(err)
			}
		}()

		log.Printf("[Website] Starting SSL website at localhost:%v\n", cfg.SSLPort)

		addr := ":" + cfg.SSLPort
		err := http.ListenAndServeTLS(addr, cfg.CertFile, cfg.KeyFile, nil)
		if err != nil {
			log.Printf("[Website] Error starting https server at localhost:%v", addr)
			log.Fatal(err)
		}
	} else {
		log.Printf("[Website] Starting website at localhost:%v\n", cfg.Port)

		addr := ":" + cfg.Port
		err := http.ListenAndServe(addr, nil)
		if err != nil {
			log.Printf("[Website] Error starting http server at localhost:%v", addr)
			log.Fatal(err)
		}
	}
}

// ---- End Website functions ---- //
