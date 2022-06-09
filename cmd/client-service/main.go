package main

import (
	"crypto/sha1"
	"fmt"
	"log"
	"time"

	"github.com/deroproject/derohe/rpc"
	"github.com/docopt/docopt-go"

	"github.com/civilware/dM/cmd/client-service/api"
	"github.com/civilware/dM/cmd/client-service/backend"
	"github.com/civilware/dM/cmd/client-service/message"
	"github.com/civilware/dM/cmd/client-service/web"

	"github.com/ybbus/jsonrpc"
)

// Mainnet TODO: Adding params for default vals like website ssl, default multiplier, default function, etc.
var command_line string = `DeroMessage-Client
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
  --scid=<805ade9294d01a8c9892c73dc7ddba012eaa0d917348f9b317b706131c82a2d5>		if defined, code will leverage custom SCID for store (this MUST be similar to this repo's .bas contract, else very similar methods or else you will get errs)`

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

var Graviton_backend *backend.GravitonStore = &backend.GravitonStore{}

// Main function that provisions persistent graviton store, gets listening wallet addr & service listeners spun up and calls looped function to keep service alive
func main() {
	var err error
	var walletEndpoint string
	var daemonEndpoint string

	pollTime, _ := time.ParseDuration("5s")
	thAddition := int64(2)

	var arguments map[string]interface{}

	if err != nil {
		log.Fatalf("[Main] Error while parsing arguments err: %s\n", err)
	}

	arguments, err = docopt.Parse(command_line, nil, true, "DERO Message Client : work in progress", false)
	_ = arguments

	log.Printf("[Main] DERO Message Service (client) :  This is under heavy development, use it for testing/evaluations purpose only\n")

	// Set variables from arguments
	walletEndpoint = "127.0.0.1:10103"
	if arguments["--rpc-server-address"] != nil {
		walletEndpoint = arguments["--rpc-server-address"].(string)
	}

	log.Printf("[Main] Using wallet RPC endpoint %s\n", walletEndpoint)

	// create wallet client
	walletRPCClient := jsonrpc.NewClient("http://" + walletEndpoint + "/json_rpc")

	// create daemon client
	daemonEndpoint = "127.0.0.1:10102"
	if arguments["--daemon-rpc-address"] != nil {
		daemonEndpoint = arguments["--daemon-rpc-address"].(string)
	}

	log.Printf("[Main] Using daemon RPC endpoint %s\n", daemonEndpoint)

	derodRPCClient := jsonrpc.NewClient("http://" + daemonEndpoint + "/json_rpc")

	// Set SCID - default to repo's default. No matter the SCID.. information is not leaked since the client handles key traversal & encrypt/decrypt messages.
	scid := "805ade9294d01a8c9892c73dc7ddba012eaa0d917348f9b317b706131c82a2d5"
	if arguments["--scid"] != nil {
		scid = arguments["--scid"].(string)
	}

	// TODO: Cleanup implementation of this a bit.. need cleaner and more defined param vs what is setup by default (api by default, perhaps local web by default as well in this implementation)
	api_use_ssl := false
	api_nonssl_addr := "127.0.0.1:8224"
	if arguments["--api-port"] != nil {
		api_nonssl_addr = "127.0.0.1:" + arguments["--api-port"].(string)
		if api_nonssl_addr != "127.0.0.1:8224" {
			log.Printf("[Main] You are using a different non-ssl API address than default, don't forget to update config.js file for the local site!")
		}
	}

	api_ssl_addr := "127.0.0.1:8225"
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

	serviceAddress := addr_result.Address

	shasum := fmt.Sprintf("%x", sha1.Sum([]byte(addr.String())))

	db_folder := fmt.Sprintf("%s_%s", PLUGIN_NAME, shasum)

	Graviton_backend.NewGravDB("deromessage", db_folder, "25ms", 5000)

	log.Printf("[Main] Persistant store for processed txids created in '%s'\n", db_folder)

	var MConfig *message.MessageConfig = &message.MessageConfig{
		Backend:         Graviton_backend,
		DerodRPCClient:  derodRPCClient,
		WalletRPCClient: walletRPCClient,
		MessageSend:     messageSend,
		PollTime:        pollTime,
		ThAddition:      thAddition,
		ServiceAddress:  serviceAddress,
		DEST_PORT:       DEST_PORT,
		SCID:            scid,
	}

	// Define website params
	var webstruct *web.Website = &web.Website{
		Enabled:  true,
		Port:     frontend_port,
		SSL:      frontend_ssl_enabled,
		SSLPort:  ssl_frontend_port,
		CertFile: "fefullchain.cer",
		KeyFile:  "fecert.key",
	}

	// Define api params
	var apistruct *api.ApiServer = &api.ApiServer{
		ApiUseSSL:     api_use_ssl,
		ApiSSLAddr:    api_ssl_addr,
		ApiNonSSLAddr: api_nonssl_addr,
		StatsIntv:     "10s",
		MessageConfig: MConfig,
	}

	//go api_process(API) // start api process / listener
	go apistruct.StartAPI()
	if webstruct.Enabled {
		go web.StartWeb(webstruct) // start web process / listener
	}

	// Start listening/processing received messages
	MConfig.ProcessReceivedMessages()
}
