package main

import (
	"fmt"
	"flag"
	"crypto/sha512"
	"encoding/base64"
	"net/http"
	"log"
	"time"
	"sync"
	"strconv"
	"encoding/json"
)

//Seconds to wait before completeing hash request
const SleepDuration = 5
//Seconds to wait on shutdown so that sending of response can happen
const SleepShutdown = 5

var srv *http.Server

//Variables related to graceful shutdown
var gShutdown bool
var gNumHashers int
var gShutdownCond *sync.Cond
var gShutdownMutex sync.Mutex

//Table holding the password hashes
var gPassTable map[int]string
var gPassTableLock sync.Mutex

//Information for generating the stats response
var gStatsLock sync.Mutex
var gRequestsTotal int
var gRequestsTime time.Duration

//For generating the key in the hash table
var gKey int
var gKeyLock sync.Mutex

func hash512(pass string) (string, error) {
	hasher := sha512.New()
	_, err := hasher.Write([]byte(pass))
	if err != nil {
		return "", err
	}
	sum := hasher.Sum(nil)
	return base64.StdEncoding.EncodeToString(sum), nil
}

// Functions for reference counting the number of 
// active threads in the system that need to complete
// before a graceful shutdown can occur
func decHashers(i int) {
	gShutdownMutex.Lock()
	gNumHashers -= i;
	if gShutdown {
		gShutdownCond.Signal()
	}
	gShutdownMutex.Unlock()
}

//Return true if incremented. False if shutdown in progress
func incHashers(i int) bool {
	gShutdownMutex.Lock()
	if gShutdown {
		gShutdownMutex.Unlock()
		return false;
	}
	gNumHashers += i;
	gShutdownMutex.Unlock()
	return true
}

func hashPass(pass string, key int, starttime time.Time) {
		time.Sleep(time.Second * SleepDuration)
		hash, err := hash512(pass)
		if err != nil {
			log.Printf("Failed to hash password %s", pass)
			decHashers(1)
			return
		}
		gPassTableLock.Lock()
		gPassTable[key] = hash
		gPassTableLock.Unlock()
		endtime := time.Now()
		duration := endtime.Sub(starttime)
		gStatsLock.Lock()
		gRequestsTotal++;
		gRequestsTime += duration
		gStatsLock.Unlock()
		decHashers(1)
}

func handleHash(writer http.ResponseWriter, request *http.Request) {
	if !incHashers(2) {
		return
	}

	starttime := time.Now()
	err := request.ParseForm()
	if err != nil {
		log.Printf("Failed to parse form: %s", err)
		http.Error(writer, err.Error(),
		    http.StatusInternalServerError)
		decHashers(2)
		return
	}
	pass := request.PostForm.Get("password")
	if pass == "" {
		log.Printf("No password found")
		http.Error(writer, "No Password found",
		    http.StatusInternalServerError)
		decHashers(2)
		return
	}

	// No requirement to make the key random or obscure
	// No ability to remove hashes specified
	// Might as well go simple with generating the key

	gKeyLock.Lock()
	key := gKey
	gKey++
	gKeyLock.Unlock()

	go hashPass(pass, key, starttime)
	
	fmt.Fprintf(writer, "%v", key)

	decHashers(1)
}

func handleGetHash(writer http.ResponseWriter, request *http.Request) {
	if !incHashers(1) {
		return
	}
	keystring := request.URL.Path[len("/hash/"):]
	key, err := strconv.Atoi(keystring)
	if err != nil {
		log.Printf("Bad key lookup %s", keystring)
		http.NotFound(writer, request)
		decHashers(1)
		return
	}
	gPassTableLock.Lock()
	hash, ok := gPassTable[key]
	gPassTableLock.Unlock()
	if !ok {
		log.Printf("Key not found %s", keystring)
		http.NotFound(writer, request)
		decHashers(1)
		return
	}
	fmt.Fprintf(writer, "%s", hash)
	decHashers(1)
}
func handleShutdown(writer http.ResponseWriter, request *http.Request) {
	gShutdownCond.L.Lock()
	gShutdown = true;
	gShutdownCond.Signal()
	gShutdownCond.L.Unlock()
}

func handleStats(writer http.ResponseWriter, request *http.Request) {
	if !incHashers(1) {
		return
	}

	gStatsLock.Lock()
	avg := 0
	if gRequestsTotal > 0 {
		duration_ms := int(gRequestsTime.Nanoseconds() / 1000000)
		avg = duration_ms / gRequestsTotal
	}
	stats := map[string]int{"total":gRequestsTotal, "average":avg}
	gStatsLock.Unlock()
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusCreated)
	err := json.NewEncoder(writer).Encode(&stats)
	if err != nil {
		log.Printf("json encoding error:", err)
		http.Error(writer, err.Error(),
		    http.StatusInternalServerError)
	}
	decHashers(1)
}

func main() {
	gShutdown = false
	gShutdownCond = sync.NewCond(&gShutdownMutex)
	gPassTable = make(map[int]string)
	var addr = flag.String("addr", ":8080", "http service addr")
	flag.Parse()
	srv = &http.Server{Addr: *addr}
	http.Handle("/hash", http.HandlerFunc(handleHash))
	http.Handle("/hash/", http.HandlerFunc(handleGetHash))
	http.Handle("/stats", http.HandlerFunc(handleStats))
	http.Handle("/shutdown", http.HandlerFunc(handleShutdown))
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Printf("ListenAndServer error: %s", err)
		}
	}()
	gShutdownCond.L.Lock()
	for !gShutdown || gNumHashers > 0 {
		gShutdownCond.Wait()
	}
	gShutdownCond.L.Unlock()
	//Let the shutdown function have time to send its response
	time.Sleep(time.Second * SleepShutdown)
	if err := srv.Shutdown(nil); err != nil {
		panic(err)
	}
}
