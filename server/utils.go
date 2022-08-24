package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost/config"
)

// UserAgent is a custom string type to avoid confusing url + userAgent parameters in SendHTTPRequest
type UserAgent string

type Validators struct {
	Message struct {
		FeeRecipient string `json:"fee_recipient"`
		GasLimit     string `json:"gas_limit"`
		Timestamp    string `json:"timestamp"`
		Pubkey       string `json:"pubkey"`
	} `json:"message"`
	Signature string `json:"signature"`
}

// SendHTTPRequest - prepare and send HTTP request, marshaling the payload if any, and decoding the response if dst is set
func SendHTTPRequest(ctx context.Context, client http.Client, method, url string, userAgent UserAgent, payload any, dst any) (code int, err error) {
	var req *http.Request
	ValidPubkey := []string{
		"0x827ec3fa631fe6b81f17ef3fda2076353bc8b8641010a0c8449614d8551265a0c08d4ebfb3242629d19302bcfe6c69b3",
		"0x81aa8d0f7c103ba602bed993a693d37483e706e7c3ed6bdd322a95b3de2ab8222881d6319300676d1e56ea71c578cca9",
		"0x8a0997757f838755983e331c6a99b335a82e5394f30e692d5851e3b1bb9dfb254053e3725001511081a890b4d156f608",
		"0x95efb3419798a95f6c95926f416407ebc88ef39cfd3bc78abc6d6edd9568cc5d4e2e4bc68467251030fdc139369dc8a4",
		"0xb9bbb013236b6080e241904ff7ff2563aca420239569e02ac33c84a64dbee6222d9444a05b29193191ac9b294e7f898c",
		"0x8cc261425674d068acb06f020c2de5b77ffc9ca5ef8c8ef4441d5c8d717673dd655e2a47aa81d1ae4506d5c762105f01",
		"0xab3ea2e4616f1820fd8b9836bdb4f1900b2ba91d9ff32fb6d1c06d0bcdfa5246064fb2392aa23b06fb0b37eb97bc25f7",
		"0x8554581aebe360a02bc696ca8d032c8f92c04311cba9d07812ea94938b241f3bac0360150c57633850ba9cbaa2dd7778",
		"0x8777c1381d54b6035180e389b8d0e01768a384ad2db5b70a98983b87a92632ed027647bcbf5f7e071a743fc8a0d7578e",
	}

	if payload == nil {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	} else {
		payloadBytes, err2 := json.Marshal(payload)
		if err2 != nil {
			return 0, fmt.Errorf("could not marshal request: %w", err2)
		}

		//TODO for handling exited validator
		newValidatorInfo := make([]Validators, 0, cap(ValidPubkey))
		vali := make([]Validators, 500, 1000)
		json.Unmarshal([]byte(payloadBytes), &vali)
		for i := 0; i < len(vali); i++ {
			for j := 0; j < len(ValidPubkey); j++ {
				if vali[i].Message.Pubkey == ValidPubkey[j] {
					newValidatorInfo = append(newValidatorInfo, vali[i])
					break
				}
			}
		}

		payloadBytes, err3 := json.Marshal(newValidatorInfo)
		if err3 != nil {
			return 0, fmt.Errorf("could not marshal request for exited validator: %w", err3)
		}
		//fmt.Println(string(payloadBytes))

		//Origin
		req, err = http.NewRequestWithContext(ctx, method, url, bytes.NewReader(payloadBytes))

		// Set content-type
		req.Header.Add("Content-Type", "application/json")
	}
	if err != nil {
		return 0, fmt.Errorf("could not prepare request: %w", err)
	}

	// Set user agent
	req.Header.Set("User-Agent", strings.TrimSpace(fmt.Sprintf("mev-boost/%s %s", config.Version, userAgent)))

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, nil
	}

	if resp.StatusCode > 299 {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, fmt.Errorf("could not read error response body for status code %d: %w", resp.StatusCode, err)
		}
		return resp.StatusCode, fmt.Errorf("HTTP error response: %d / %s", resp.StatusCode, string(bodyBytes))
	}

	if dst != nil {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, fmt.Errorf("could not read response body: %w", err)
		}

		if err := json.Unmarshal(bodyBytes, dst); err != nil {
			return resp.StatusCode, fmt.Errorf("could not unmarshal response %s: %w", string(bodyBytes), err)
		}
	}

	return resp.StatusCode, nil
}

// ComputeDomain computes the signing domain
func ComputeDomain(domainType types.DomainType, forkVersionHex string, genesisValidatorsRootHex string) (domain types.Domain, err error) {
	genesisValidatorsRoot := types.Root(common.HexToHash(genesisValidatorsRootHex))
	forkVersionBytes, err := hexutil.Decode(forkVersionHex)
	if err != nil || len(forkVersionBytes) > 4 {
		err = errors.New("invalid fork version passed")
		return domain, err
	}
	var forkVersion [4]byte
	copy(forkVersion[:], forkVersionBytes[:4])
	return types.ComputeDomain(domainType, forkVersion, genesisValidatorsRoot), nil
}

// DecodeJSON reads JSON from io.Reader and decodes it into a struct
func DecodeJSON(r io.Reader, dst any) error {
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		return err
	}
	return nil
}

// bidResp are entries in the bids cache
type bidResp struct {
	t         time.Time
	response  types.GetHeaderResponse
	blockHash string
	relays    []string
}

// bidRespKey is used as key for the bids cache
type bidRespKey struct {
	slot      uint64
	blockHash string
}
