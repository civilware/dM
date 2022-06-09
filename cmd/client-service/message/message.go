package message

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/civilware/dM/cmd/client-service/backend"
	"github.com/deroproject/derohe/rpc"
	"github.com/ybbus/jsonrpc"
	"golang.org/x/crypto/chacha20poly1305"
)

type MessageConfig struct {
	MessageSend     rpc.Arguments
	WalletRPCClient jsonrpc.RPCClient
	DerodRPCClient  jsonrpc.RPCClient
	Backend         *backend.GravitonStore
	ThAddition      int64
	PollTime        time.Duration
	ServiceAddress  string
	DEST_PORT       uint64
	SCID            string
}

type SendMessageEntry struct {
	Username    string `json:"contactname"`
	Messagetext string `json:"messagetext"`
	Messagetags string `json:"messagetags"`
}

var prevTH int64

func (m *MessageConfig) ProcessSendingMessages(varname string, plaintext string, destinationAddresses string, messagetags string) string {
	// Version 2 TODO: messagetags are leveraged for replying/forwarding messages

	// Check if the variable already exists, if it does exit out (FOR NOW), possibly add --overwrite option or something for data recycling at a later time
	log.Printf("[processSendingMessages] Checking '%v' to see if it is already used in SC.", varname)
	varTap := checkUserKeyResults(varname, m)
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

	var tparams rpc.Transfer_Params
	tparams, err = encryptAndSend(passwordKey, plaintext, varname, m)
	if err != nil {
		log.Printf("[processSendingMessages] Err encrypting and sending: \n%v", err)
		return fmt.Sprintf("ERR: Err encrypting and sending - %v", err)
	}

	var messageSend = m.MessageSend

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
			if trimAddress == m.ServiceAddress {
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
		if trimAddress == m.ServiceAddress {
			log.Printf("[processSendingMessages] destination address is the same as the source. Please check your 'TO' field to ensure you aren't sending to yourself.")
			return fmt.Sprintf("ERR: destination address is the same as the source. Please check your 'TO' field to ensure you aren't sending to yourself.")
		}

		transfers = append(transfers, rpc.Transfer{Destination: trimAddress, Amount: uint64(1), Payload_RPC: messageSend})
	}

	tparams.Transfers = transfers

	log.Printf("[processSendingMessages] Sending transfers tx...")
	txSendRes := sendTx(tparams, varname, passwordKey, m)

	var results string

	if txSendRes == "" {
		results = "Successfully sent message!"
	} else {
		results = txSendRes
	}

	return results
}

func (m *MessageConfig) ProcessReceivedMessages() {

	for { // currently we traverse entire history with a few filters

		time.Sleep(m.PollTime)

		var transfers rpc.Get_Transfers_Result
		err := m.WalletRPCClient.CallFor(&transfers, "GetTransfers", rpc.Get_Transfers_Params{In: true, SourcePort: m.DEST_PORT, DestinationPort: m.DEST_PORT})
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
				//time.Sleep(10 * time.Second)
				continue
			}

			passwordKey, err := hex.DecodeString(passwordString)

			if err != nil {
				log.Printf("[processReceivedMessages] Error decoding decryptionkey for SC var %v . Will circle back around and try again", varName) // Mainnet TODO: Fix for proper error handling such as exclude tx or note message to be "unopenable" or something
				continue
			}

			// Get txDetail [sender+txid] from graviton store, if received it is already processed else continue
			txDetails := m.Backend.GetTXs()

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
				m.DEST_PORT != e.Payload_RPC.Value(rpc.RPC_SOURCE_PORT, rpc.DataUint64).(uint64) {

				log.Printf("[processReceivedMessages] Tx doesn't meet filter requirements...")
				//time.Sleep(10 * time.Second)
				continue
			}

			var txTime int64
			txTime = (e.Time.UnixNano() / int64(time.Millisecond)) / 1000
			decryptedText := receiveAndDecrypt(passwordKey, varName, e.TXID, e.Sender, txTime, m)
			if decryptedText != "" {
				log.Printf("[processReceivedMessages] DecryptedText: \n%v", decryptedText)
			} else {
				log.Printf("[processReceivedMessages] Unable to get decrypted text yet, will circle back..")
			}
		}
	}
}

func encryptAndSend(key []byte, plaintext string, varname string, m *MessageConfig) (t rpc.Transfer_Params, err error) {
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
		Using chacha20poly1305 NewX - https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305#NewX

		XChaCha20-Poly1305 is a ChaCha20-Poly1305 variant that takes a longer nonce, suitable to be generated randomly without risk of collisions.
		It should be preferred when nonce uniqueness cannot be trivially ensured, or whenever nonces are randomly generated.
	*/
	nonce := make([]byte, chacha20poly1305.NonceSizeX, chacha20poly1305.NonceSizeX)
	cipher, err := chacha20poly1305.NewX(key)
	if err != nil {
		log.Printf("[encryptAndSend] Err generating chacha20poly1305 cipher: %v", err)
		return t, err
	}

	_, err = rand.Read(nonce)
	if err != nil {
		log.Printf("[encryptAndSend] Err randomly reading nonce: %v", err)
		return t, err
	}

	Data := []byte(plaintext)

	Data = cipher.Seal(Data[:0], nonce, Data, nil)

	encResult := append(Data, nonce...)

	log.Printf("[encryptAndSend] Encrypted text: %v", encResult)
	ciphertext := hex.EncodeToString(encResult)
	log.Printf("[encryptAndSend] Ciphertext: %v", ciphertext)

	// Future TODO: If compression is required/used, define it here

	/* Call SC - this is to input data into a SC that just takes a simple string and stores it to a simple var [single TX store compressed & encoded txt to be pulled from later]*/
	var gasstr rpc.GasEstimate_Result
	var rpcArgs = rpc.Arguments{}
	rpcArgs = append(rpcArgs, rpc.Argument{Name: "entrypoint", DataType: "S", Value: "InputStr"})
	rpcArgs = append(rpcArgs, rpc.Argument{Name: "input", DataType: "S", Value: string(ciphertext)})
	rpcArgs = append(rpcArgs, rpc.Argument{Name: "varname", DataType: "S", Value: varname})

	gasRpc := rpcArgs
	gasRpc = append(gasRpc, rpc.Argument{Name: "SC_ACTION", DataType: "U", Value: 0})
	gasRpc = append(gasRpc, rpc.Argument{Name: "SC_ID", DataType: "H", Value: string([]byte(m.SCID))})
	gasestimateparams := rpc.GasEstimate_Params{SC_ID: m.SCID, SC_RPC: gasRpc}
	err = m.DerodRPCClient.CallFor(&gasstr, "DERO.GetGasEstimate", gasestimateparams)
	if err != nil {
		log.Printf("[encryptAndSend] gas estimate err %s\n", err)
	} else {
		log.Printf("[encryptAndSend] gas estimate results: %v", gasstr)
	}

	// TODO: Perhaps we call this (getgasestimate) first, return to UI and then ask user to confirm.
	// For now, just passthru and append fees onto the transfer and go
	gasestimateparams.Fees = gasstr.GasStorage

	return rpc.Transfer_Params(gasestimateparams), nil
}

func receiveAndDecrypt(key []byte, scVarName string, txid string, sender string, txtime int64, m *MessageConfig) string {
	//Receive from SC and decode results, comment out until I put in functions etc..
	var results string
	for {
		results = checkUserKeyResults(scVarName, m)

		resCheck := strings.Split(results, ":")

		if resCheck[0] == "NOT AVAILABLE err" {
			log.Printf("[receiveAndDecrypt] No key found yet for %v, will circle back...", scVarName)
			//time.Sleep(10 * time.Second)
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
	newTxDetails := &backend.TXDetails{ScValue: scVarName, Key: key, RawMessage: decryptedText, Txid: txid, Sender: sender, TimeStamp: txtime}
	err = m.Backend.StoreTX(newTxDetails)

	if err != nil {
		log.Printf("[receiveAndDecrypt] err updating db to err %s\n", err)
	} else {
		log.Printf("[receiveAndDecrypt] TX Received and stored")
	}

	return decryptedText
}

func checkUserKeyResults(userKey string, m *MessageConfig) string {
	// Grab userKey value from SC
	var scstr *rpc.GetSC_Result
	var strings []string
	strings = append(strings, userKey)
	getSC := rpc.GetSC_Params{SCID: m.SCID, Code: false, KeysString: strings}
	err := m.DerodRPCClient.CallFor(&scstr, "getsc", getSC)
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

func sendTx(tparams rpc.Transfer_Params, scvalue string, key []byte, m *MessageConfig) string {
	// sender of ping now becomes destination
	var str rpc.Transfer_Result

	if prevTH != 0 {
		for {
			var info rpc.GetInfo_Result
			err := m.DerodRPCClient.CallFor(&info, "get_info")
			if err != nil {
				return fmt.Sprintf("ERR: %v", err)
			}

			targetTH := prevTH + m.ThAddition

			if targetTH <= info.TopoHeight {
				prevTH = info.TopoHeight
				break
			} else {
				log.Printf("[sendTX] Waiting until topoheights line up to send next TX [last: %v / curr: %v]", info.TopoHeight, targetTH)
				time.Sleep(m.PollTime)
			}
		}
	} else {
		var info rpc.GetInfo_Result
		err := m.DerodRPCClient.CallFor(&info, "get_info")
		if err != nil {
			return fmt.Sprintf("ERR: %v", err)
		}

		prevTH = info.TopoHeight
	}

	err := m.WalletRPCClient.CallFor(&str, "Transfer", tparams)
	if err != nil {
		log.Printf("[sendTx] err: %v", err)
		return fmt.Sprintf("ERR: %v", err)
	} else {
		log.Printf("[sendTx] Tx sent successfully - txid: %v", str.TXID)
	}

	for _, v := range tparams.Transfers {
		if tparams.Transfers != nil {
			// Store new txdetails in graviton store
			timestamp := (time.Now().UnixNano() / int64(time.Millisecond)) / 1000
			newTxDetails := &backend.SendDetails{Recipient: v.Destination, ScValue: scvalue, Key: key, TimeStamp: timestamp}
			err := m.Backend.StoreSentTX(newTxDetails)

			if err != nil {
				log.Printf("[sendTx] err updating db to err %s\n", err)
			} else {
				log.Printf("[sendTx] TX Sent and stored")
			}
		}
	}

	return ""
}
