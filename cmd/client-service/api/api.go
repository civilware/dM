package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/civilware/dM/cmd/client-service/backend"
	"github.com/civilware/dM/cmd/client-service/message"

	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"

	"github.com/gorilla/mux"
)

type ApiServer struct {
	Stats         atomic.Value
	StatsIntv     string
	ApiUseSSL     bool
	ApiSSLAddr    string
	ApiNonSSLAddr string
	MessageConfig *message.MessageConfig
}

const API_CERTFILE = "apifullchain.cer"
const API_KEYFILE = "apicert.key"

// Keep api running
func (api *ApiServer) StartAPI() {
	statsIntv, _ := time.ParseDuration(api.StatsIntv)
	statsTimer := time.NewTimer(statsIntv)
	log.Printf("[API] Set stats collect interval to %v", statsIntv)

	api.collectStats()

	go func() {
		for {
			select {
			case <-statsTimer.C:
				api.collectStats()
				statsTimer.Reset(statsIntv)
			}
		}
	}()

	// If SSL is configured, due to nature of listenandserve, put HTTP in go routine then call SSL afterwards so they can run in parallel. Otherwise, run http as normal
	if api.ApiUseSSL {
		go api.apiListen()
		api.apiListenSSL()
	} else {
		api.apiListen()
	}
}

// API Server listen over non-SSL
func (api *ApiServer) apiListen() {
	log.Printf("[API] Starting API on %v", api.ApiNonSSLAddr)
	router := mux.NewRouter()
	// TODO: Add other apis for button clicking / running commands internal like register, send messages, receive messages (refresh? or ignore and just it is auto-refresh based on param.. will see)
	router.HandleFunc("/api/stats", api.statsIndex)
	router.HandleFunc("/api/sendmessage", api.sendMessageCall)
	router.NotFoundHandler = http.HandlerFunc(notFound)
	err := http.ListenAndServe(api.ApiNonSSLAddr, router)
	if err != nil {
		log.Fatalf("[API] Failed to start API: %v", err)
	}
}

// API Server listen over SSL
func (api *ApiServer) apiListenSSL() {
	log.Printf("[API] Starting SSL API on %v", api.ApiSSLAddr)
	routerSSL := mux.NewRouter()
	// TODO: Add other apis for button clicking / running commands internal like register, send messages, receive messages (refresh? or ignore and just it is auto-refresh based on param.. will see)
	routerSSL.HandleFunc("/api/stats", api.statsIndex)
	routerSSL.HandleFunc("/api/sendmessage", api.sendMessageCall)
	routerSSL.NotFoundHandler = http.HandlerFunc(notFound)
	err := http.ListenAndServeTLS(api.ApiSSLAddr, API_CERTFILE, API_KEYFILE, routerSSL)
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
func (api *ApiServer) collectStats() {
	stats := make(map[string]interface{})

	// Get Inbox TX
	var apiTxs []*backend.TXDetails
	inboxTxs := api.MessageConfig.Backend.GetTXs()

	for _, v := range inboxTxs {
		if inboxTxs != nil {
			if v != nil {
				txDetail := &backend.TXDetails{ScValue: v.ScValue, Key: v.Key, RawMessage: v.RawMessage, Txid: v.Txid, Sender: v.Sender, TimeStamp: v.TimeStamp}

				apiTxs = append(apiTxs, txDetail)
			}
		}
	}

	// Get Sent TX
	var apiSentTxs []*backend.SendDetails

	sentTxs := api.MessageConfig.Backend.GetSentTXs()

	for _, v := range sentTxs {
		if sentTxs != nil {
			if v != nil {
				txDetail := &backend.SendDetails{TimeStamp: v.TimeStamp, Recipient: v.Recipient, ScValue: v.ScValue, Key: v.Key}

				apiSentTxs = append(apiSentTxs, txDetail)
			}
		}
	}

	// Wallet balance
	// Test rpc-server connection to ensure wallet connectivity, exit out if not
	// TODO: Is wallet balance necessary? Perhaps.. since it's small TX fees to send an message (free to receive, unless implementing validation of sender address but may not be needed)
	var balance_result *rpc.GetBalance_Result
	err := api.MessageConfig.WalletRPCClient.CallFor(&balance_result, "getbalance")

	if err != nil {
		log.Printf("[API-collectStats] Err getting balance from walletrpc.")
	} else {
		stats["walletBalance"] = globals.FormatMoney(balance_result.Balance)
	}

	stats["inboxMessages"] = apiTxs
	stats["sentMessages"] = apiSentTxs

	api.Stats.Store(stats)
}

// API StatsIndex
func (api *ApiServer) statsIndex(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "application/json; charset=UTF-8")
	writer.Header().Set("Access-Control-Allow-Origin", "*")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.WriteHeader(http.StatusOK)

	reply := make(map[string]interface{})

	stats := api.getStats()
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
func (api *ApiServer) sendMessageCall(writer http.ResponseWriter, req *http.Request) {
	writer.Header().Set("Content-Type", "application/json; charset=UTF-8")
	writer.Header().Set("Access-Control-Allow-Origin", "*")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.WriteHeader(http.StatusOK)

	var sendMessageInput message.SendMessageEntry

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

	sendResults := api.MessageConfig.ProcessSendingMessages(varname, sendMessageInput.Messagetext, sendMessageInput.Username, sendMessageInput.Messagetags)

	reply := sendResults

	err = json.NewEncoder(writer).Encode(reply)
	if err != nil {
		log.Printf("[API-sendMessageCall] Error serializing API response: %v", err)
	}
}

// API Get stats from backend
func (api *ApiServer) getStats() map[string]interface{} {
	stats := api.Stats.Load()
	if stats != nil {
		return stats.(map[string]interface{})
	}
	return nil
}
