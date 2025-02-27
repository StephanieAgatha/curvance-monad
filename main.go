package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

func sendTokenApproval(client *ethclient.Client, privateKey *ecdsa.PrivateKey, tokenAddress string, spenderAddress string, amount *big.Int) (string, error) {
	ctx := context.Background()

	chainID, err := client.ChainID(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get chain ID: %v", err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("failed to get public key")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	nonce, err := client.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		return "", fmt.Errorf("failed to get nonce: %v", err)
	}

	gasTipCap, err := client.SuggestGasTipCap(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get gas tip cap: %v", err)
	}

	header, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get block header: %v", err)
	}
	baseFee := header.BaseFee

	bufferGwei := big.NewInt(30_000_000_000)
	baseFeeMul := new(big.Int).Mul(baseFee, big.NewInt(2))
	option1 := new(big.Int).Add(baseFeeMul, gasTipCap)
	option2 := new(big.Int).Add(gasTipCap, bufferGwei)

	gasFeeCapNew := option1
	if option2.Cmp(option1) > 0 {
		gasFeeCapNew = option2
	}

	gasLimit := uint64(100000)

	_ = common.HexToAddress(spenderAddress)
	tokenContract := common.HexToAddress(tokenAddress)
	data := []byte{0x39, 0x5e, 0xa6, 0x1b}

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasTipCap: gasTipCap,
		GasFeeCap: gasFeeCapNew,
		Gas:       gasLimit,
		To:        &tokenContract,
		Value:     big.NewInt(0),
		Data:      data,
	})

	signedTx, err := types.SignTx(tx, types.NewLondonSigner(chainID), privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %v", err)
	}

	err = client.SendTransaction(ctx, signedTx)
	if err != nil {
		return "", fmt.Errorf("failed to send transaction: %v", err)
	}

	return signedTx.Hash().Hex(), nil
}

func loadPrivateKeys(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open private key file: %v", err)
	}
	defer file.Close()

	var keys []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key := strings.TrimSpace(scanner.Text())
		if key != "" {
			keys = append(keys, strings.TrimPrefix(key, "0x"))
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading private key file: %v", err)
	}

	return keys, nil
}

func main() {
	rpcURL := "https://monad-testnet.g.alchemy.com/v2/CLH8wkezJtaijaOWTQEv78CRnIEWKE0H"
	tokenAddress := "0x8462c247356d7deb7e26160dbfab16b351eef242"
	spenderAddress := "0x0000000000000000000000000000000000000000"

	amount := new(big.Int)
	amount.SetString("1000000000000000000", 10)

	fmt.Print("Input delay (seconds): ")
	var delayInput string
	fmt.Scanln(&delayInput)

	delay, err := strconv.Atoi(delayInput)
	if err != nil {
		log.Fatalf("Invalid delay input: %v", err)
	}

	privateKeys, err := loadPrivateKeys("pk.txt")
	if err != nil {
		log.Fatalf("Failed to load private keys: %v", err)
	}

	if len(privateKeys) == 0 {
		log.Fatal("No private keys found in pk.txt")
	}

	rpcClient, err := rpc.Dial(rpcURL)
	if err != nil {
		log.Fatalf("Failed to connect to Ethereum node: %v", err)
	}

	client := ethclient.NewClient(rpcClient)

	for {
		for i, pkHex := range privateKeys {
			privateKey, err := crypto.HexToECDSA(pkHex)
			if err != nil {
				log.Printf("Failed to parse private key %d: %v", i+1, err)
				continue
			}

			txHash, err := sendTokenApproval(client, privateKey, tokenAddress, spenderAddress, amount)
			if err != nil {
				log.Printf("Failed to send approval transaction from wallet %d: %v", i+1, err)
				continue
			}

			fmt.Printf("Pumped! tx: %s\n", txHash)

			// sleep between wallets
			if len(privateKeys) > 1 && i < len(privateKeys)-1 {
				time.Sleep(time.Duration(delay) * time.Second)
			}
		}

		// sleep after full cycle
		time.Sleep(time.Duration(delay) * time.Second)
	}
}
