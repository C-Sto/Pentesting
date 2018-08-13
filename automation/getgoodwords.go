package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "net/http/pprof"
)

/*
mv passwords.txt oldpasswords.txt

for x in {0..999}
        do echo "WORKING:$x"
        curl -X $'GET' -H $'Host: hashes.org' -H $'Referer: https://hashes.org/' -H $'Accept-Encoding: gzip, deflate' "https://hashes.org/download.php?type=found&hashlistId=$x" >> passwords.txt
done


cat passwords.txt | sort | uniq -c | sort -nr | sed 's/^ *[0-9]* //' > goodwordlistsortedyay.txt
*/
/*
#store all wordlists from hashes.org
- Head each wordlist, check length vs what we downloaded

*/

var hashesNumber = 999
var threadCount = 1

var tx = &http.Transport{
	DialContext: (&net.Dialer{
		//transports don't have default timeouts because having sensible defaults would be too good
		Timeout: 3 * time.Second,
	}).DialContext,
	TLSHandshakeTimeout:   30 * time.Second,
	MaxIdleConns:          100, //This could potentially be dropped to 1, we aren't going to hit the same server more than once ever
	IdleConnTimeout:       5 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	DisableKeepAlives:     false,
	DisableCompression:    false,
	TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
}

var cl = http.Client{
	Transport: tx,
	//Timeout:   time.Second * , //eyy no reasonable timeout on clients too!
}

func downloadFileToLocal(req *http.Request, localPath string, outputChan chan string) {

	dirpath := filepath.Dir(localPath)
	if _, err := os.Stat(dirpath); os.IsNotExist(err) {
		os.MkdirAll(dirpath, os.ModePerm)
	}

	//create file
	out, err := os.Create(localPath)
	defer out.Close()

	finishedDl := make(chan int64)

	resp, err := cl.Do(req)
	if err != nil {
		outputChan <- fmt.Sprintf("ERROR: %s", err.Error())
	}
	defer resp.Body.Close()

	go func() {
		ticker := time.NewTicker(time.Second * 5)
		for {
			select {
			case <-finishedDl:
				return
			case <-ticker.C:
				fi, _ := os.Stat(localPath)
				localSize := fi.Size()
				outputChan <- fmt.Sprintf("Downloading: %s %d/%d", req.URL, localSize, resp.ContentLength)
			}
		}
	}()

	n, err := io.Copy(out, resp.Body)
	finishedDl <- n
	if err != nil {
		fmt.Println(err)
	}

}

type hashesDotOrgUrl struct {
	BreachNumber int
	Url          string
}

var hashesDir = "./fullwordlists/hashes.org"

func main() {

	//profiling code - handy when dealing with concurrency and deadlocks ._.
	go func() {
		http.ListenAndServe("localhost:6061", http.DefaultServeMux)
	}()

	wg := sync.WaitGroup{}

	//build local dir

	headChan := make(chan hashesDotOrgUrl, hashesNumber) //channel to fill with head requests
	getChan := make(chan hashesDotOrgUrl, hashesNumber)  //channel to fill with get requests for successful head requests
	outChan := make(chan string, 10)

	go tickUpdate(getChan, outChan)
	go stoutWriter(outChan)

	wg.Add(1)
	go doGets(getChan, &wg, outChan)
	wg.Add(1)
	go doHeads(headChan, getChan, &wg, outChan)
	wg.Add(1)
	go fillHeadHashesOrg(headChan, &wg)

	wg.Wait()
	fmt.Println("Done!")
}

func tickUpdate(getChan chan hashesDotOrgUrl, outChan chan string) {
	tick := time.NewTicker(time.Second * 10)
	for _ = range tick.C {
		outChan <- fmt.Sprintf("Dl Queue: %d\n", len(getChan))
	}
}

func stoutWriter(outChan chan string) {
	for {
		s := <-outChan
		fmt.Println(s)
	}
}

func fillHeadHashesOrg(headChan chan hashesDotOrgUrl, wg *sync.WaitGroup) {
	defer wg.Done()
	for x := 0; x < hashesNumber; x++ {
		headChan <- hashesDotOrgUrl{
			Url:          fmt.Sprintf("https://hashes.org/download.php?type=found&hashlistId=%d", x),
			BreachNumber: x,
		}
	}
	close(headChan)
}

func doGets(getChan chan hashesDotOrgUrl, wg *sync.WaitGroup, outChan chan string) {
	defer func() {
		wg.Done()
	}()
	inwg := sync.WaitGroup{}
	threads := make(chan struct{}, threadCount) //currently 1 to avoid abuse, maybe increase eventually
	for url := range getChan {
		threads <- struct{}{}
		inwg.Add(1)
		outChan <- "Getting " + url.Url
		go doGet(url, &inwg, outChan, threads)
	}

	inwg.Wait()
}

func doGet(url hashesDotOrgUrl, wg *sync.WaitGroup, outChan chan string, t chan struct{}) {

	defer wg.Done()

	fullpath := hashesDir + string(os.PathSeparator) + fmt.Sprintf("%d.words", url.BreachNumber)
	req, _ := http.NewRequest("GET", url.Url, nil)
	req.Header.Set("Referer", "https://hashes.org/") //set dat referrer

	downloadFileToLocal(req, fullpath, outChan)
	<-t

}

func doHeads(headChan chan hashesDotOrgUrl, getChan chan hashesDotOrgUrl, outerWg *sync.WaitGroup, outChan chan string) {
	defer func() {
		outerWg.Done()

	}()
	threads := make(chan struct{}, 5) //5 threads to do heads b/c idk?
	wg := sync.WaitGroup{}
	for {
		//check if we can read form headChan, or if it's closed
		url, recv := <-headChan
		if !recv {
			break
			//indicates it's closed, wait for remaining threads and exit func
		}
		//block if we're using too many threads already
		threads <- struct{}{}
		//add to waitgroup
		wg.Add(1)
		//spin off worker
		go doHead(url, getChan, &wg, threads, outChan)
	}
	wg.Wait()
	close(getChan)

}

func doHead(url hashesDotOrgUrl, getChan chan hashesDotOrgUrl, wg *sync.WaitGroup, threads chan struct{}, outChan chan string) {
	defer func() {
		<-threads
		wg.Done()
	}()
	fullpath := hashesDir + string(os.PathSeparator) + fmt.Sprintf("%d.words", url.BreachNumber)
	req, _ := http.NewRequest("HEAD", url.Url, nil)
	req.Header.Set("Referer", "https://hashes.org/") //set dat referrer
	resp, err := cl.Do(req)
	if err != nil {
		return
	}
	outChan <- fmt.Sprintf("Head: %d %d", url.BreachNumber, resp.ContentLength)
	if resp.ContentLength < 10 {
		return
	}
	//check if local file exists
	if fi, err := os.Stat(fullpath); os.IsNotExist(err) {
		outChan <- fmt.Sprintf("File doesn't exist, adding to dl Queue: %d", url.BreachNumber)
		getChan <- url
	} else if fi != nil {
		//file exists, check sizes to see if different
		size := fi.Size()
		if size != resp.ContentLength {
			outChan <- fmt.Sprintf("File exists locally, but length differs, downloading: %d", url.BreachNumber)
			os.Remove(fullpath) //remove the existing file
			//downloadFileToLocal(req, fullpath) //download it again
			getChan <- url
		}
	}
}

