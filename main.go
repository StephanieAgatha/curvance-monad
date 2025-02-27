package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

var (
	spinnerStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("63"))
	txStyle        = lipgloss.NewStyle().Foreground(lipgloss.Color("81"))
	errorStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	waitingStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("208"))
	walletStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("99"))
	completedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("105"))
	helpStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Margin(1, 0)
	appStyle       = lipgloss.NewStyle().Margin(1, 2, 0, 2)
)

type txResultMsg struct {
	txHash  string
	wallet  string
	index   int
	success bool
	err     error
}

func (r txResultMsg) String() string {
	if r.success {
		return fmt.Sprintf("%s Pumped! tx: %s",
			walletStyle.Render(fmt.Sprintf("Wallet %d", r.index+1)),
			txStyle.Render(r.txHash))
	}
	return errorStyle.Render(fmt.Sprintf("Wallet %d error: %v", r.index+1, r.err))
}

type waitMsg struct {
	seconds int
	reason  string
}

func (w waitMsg) String() string {
	return waitingStyle.Render(fmt.Sprintf("Waiting %d seconds - %s", w.seconds, w.reason))
}

type model struct {
	spinner    spinner.Model
	messages   []string
	processing bool
	quitting   bool
}

func newModel() model {
	const numLastMessages = 10
	s := spinner.New()
	s.Style = spinnerStyle
	return model{
		spinner:    s,
		messages:   make([]string, 0, numLastMessages),
		processing: true,
	}
}

func (m model) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" {
			m.quitting = true
			return m, tea.Quit
		}
		return m, nil

	case txResultMsg:
		m.messages = append([]string{msg.String()}, m.messages...)
		if len(m.messages) > 20 {
			m.messages = m.messages[:20]
		}

		return m, nil

	case waitMsg:
		m.messages = append([]string{msg.String()}, m.messages...)
		if len(m.messages) > 20 {
			m.messages = m.messages[:20]
		}
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	default:
		return m, nil
	}
}

func (m model) View() string {
	var s string

	if m.quitting {
		s += completedStyle.Render("Transaction process completed!")
	} else {
		s += m.spinner.View() + " Processing transactions..."
	}
	s += "\n\n"
	for _, msg := range m.messages {
		s += msg + "\n"
	}

	if !m.quitting {
		s += helpStyle.Render("Press 'q' to exit")
	}

	return appStyle.Render(s)
}

func clearScreen() {
	switch runtime.GOOS {
	case "windows":
		fmt.Print("\033[2J\033[H")
		fmt.Print("\x1b[3J\x1b[H")
	case "linux", "darwin":
		fmt.Print("\033[2J\033[H")
	default:
		fmt.Print("\033[2J\033[H")
	}
}

func runTransactions(p *tea.Program, client *ethclient.Client, wallets []string, tokenAddress string, spenderAddress string) {
	for {
		for i, pkHex := range wallets {
			privateKey, err := crypto.HexToECDSA(pkHex)
			if err != nil {
				p.Send(txResultMsg{
					index:   i,
					wallet:  pkHex[:8] + "...",
					success: false,
					err:     fmt.Errorf("failed to parse private key: %v", err),
				})
				continue
			}

			// send tx
			txHash, err := sendTokenApproval(client, privateKey, tokenAddress, spenderAddress)
			if err != nil {
				p.Send(txResultMsg{
					index:   i,
					wallet:  pkHex[:8] + "...",
					success: false,
					err:     err,
				})
				continue
			}

			// return successful result
			p.Send(txResultMsg{
				txHash:  txHash,
				wallet:  pkHex[:8] + "...",
				index:   i,
				success: true,
			})

			// random delay between wallets
			if len(wallets) > 1 && i < len(wallets)-1 {
				randomDelay := 5 + rand.Intn(6)
				p.Send(waitMsg{
					seconds: randomDelay,
					reason:  "before next wallet",
				})
				time.Sleep(time.Duration(randomDelay) * time.Second)
			}
		}

		// random delay between cycles
		randomDelay := 5 + rand.Intn(6)
		p.Send(waitMsg{
			seconds: randomDelay,
			reason:  "before next cycle",
		})
		time.Sleep(time.Duration(randomDelay) * time.Second)
	}
}

func sendTokenApproval(client *ethclient.Client, privateKey *ecdsa.PrivateKey, tokenAddress string, spenderAddress string) (string, error) {
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

	// get nonce
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

	// calculate gas fee cap
	bufferGwei := big.NewInt(30_000_000_000)
	baseFeeMul := new(big.Int).Mul(baseFee, big.NewInt(2))
	option1 := new(big.Int).Add(baseFeeMul, gasTipCap)
	option2 := new(big.Int).Add(gasTipCap, bufferGwei)

	// choose the higher gas fee cap
	gasFeeCapNew := option1
	if option2.Cmp(option1) > 0 {
		gasFeeCapNew = option2
	}
	gasLimit := uint64(100000)

	tokenContract := common.HexToAddress(tokenAddress)
	data := []byte{0x39, 0x5e, 0xa6, 0x1b}

	// create tx
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

	// sign tx
	signedTx, err := types.SignTx(tx, types.NewLondonSigner(chainID), privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %v", err)
	}

	// send tx
	err = client.SendTransaction(ctx, signedTx)
	if err != nil {
		return "", fmt.Errorf("failed to send transaction: %v", err)
	}

	// return tx hash
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
	rand.Seed(time.Now().UnixNano())

	rpcURL := "https://monad-testnet.g.alchemy.com/v2/CLH8wkezJtaijaOWTQEv78CRnIEWKE0H"
	tokenAddress := "0x8462c247356d7deb7e26160dbfab16b351eef242"
	spenderAddress := "0x0000000000000000000000000000000000000000"

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

	//clear screen first
	clearScreen()

	//run tea
	p := tea.NewProgram(newModel())

	// start tx in seperate goroutiness
	go runTransactions(p, client, privateKeys, tokenAddress, spenderAddress)

	if _, err := p.Run(); err != nil {
		fmt.Println("Error running program:", err)
		os.Exit(1)
	}
}
