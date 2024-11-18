package main

import (
	"encoding/json"
	"fmt"
	"github.com/projectdiscovery/goflags"
	"log"

	"github.com/Explorer1092/httpx/runner"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose) // increase the verbosity (optional)

	options := runner.Options{
		Methods: "GET",
		//InputTargetHost: goflags.StringSlice{"117.131.57.38,ipsec2.wz-inc.com,http://ipsec2.wz-inc.com:8090/"},
		//test.ai2me.io
		InputTargetHost: goflags.StringSlice{
			"8.219.49.206,xx.ai2me.io,http://test.ai2me.io/",
		},
		//InputTargetHost: goflags.StringSlice{"8.219.49.206,http://test.ai2me.io/"},
		//InputTargetHost: goflags.StringSlice{"117.131.57.38,http://ipsec2.wz-inc.com:8090/"},
		ExtractTitle: true,
		OutputCDN:    "true",
		Unsafe:       false,
		Debug:        true,
		Trace:        true,
		OnResult: func(r runner.Result) {
			// handle error
			if r.Err != nil {
				fmt.Printf("[Err] %s: %s\n", r.Input, r.Err)
				return
			}
			marshal, err := json.Marshal(r)
			if err != nil {
				return
			}
			fmt.Printf("%s\n", marshal)
		},
	}

	if err := options.ValidateOptions(); err != nil {
		log.Fatal(err)
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		log.Fatal(err)
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration()
}
