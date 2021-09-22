package main

import (
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/zricethezav/gitleaks/v7/config"
	"github.com/zricethezav/gitleaks/v7/options"
	"github.com/zricethezav/gitleaks/v7/scan"

	"github.com/dustin/go-humanize"
	"github.com/hako/durafmt"
	log "github.com/sirupsen/logrus"
)

func main() {

	// state of memory
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		var ms runtime.MemStats
		for {
			select {
			case <-ticker.C:
				runtime.ReadMemStats(&ms)
				log.Printf("Mem Sys: %v, HeapAlloc: %v, HeapInuse: %v, HeapIdle: %v, HeapReleased: %v, NextGC: %v\n",
					humanize.Bytes(ms.Sys), humanize.Bytes(ms.HeapAlloc), humanize.Bytes(ms.HeapInuse), humanize.Bytes(ms.HeapIdle),
					humanize.Bytes(ms.HeapReleased), humanize.Bytes(ms.NextGC))
			}
		}

	}()

	// profile
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	// this block sets up a go routine to listen for an interrupt signal
	// which will immediately exit gitleaks
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt)
	go listenForInterrupt(stopChan)

	// setup options
	opts, err := options.ParseOptions()
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	err = opts.Guard()
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	// setup configs
	cfg, err := config.NewConfig(opts)
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	// setup scanner
	log.Info(opts)
	log.Info(cfg)
	scanner, err := scan.NewScanner(opts, cfg)
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	// run and time the scan
	start := time.Now()
	scannerReport, err := scanner.Scan()
	log.Info("scan time: ", durafmt.Parse(time.Now().Sub(start)))
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	// report scan
	if err := scan.WriteReport(scannerReport, opts, cfg); err != nil {
		log.Error(err)
		os.Exit(1)
	}

	if len(scannerReport.Leaks) != 0 {
		os.Exit(opts.CodeOnLeak)
	}
}

func listenForInterrupt(stopScan chan os.Signal) {
	<-stopScan
	log.Warn("halting gitleaks scan")
	os.Exit(1)
}
