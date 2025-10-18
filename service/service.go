package main

import (
	"flag"
	"os"

	"github.com/dryaf/dnsfilter/lib"
	"github.com/kardianos/service"
	"golang.org/x/exp/slog"
)

var (
	// These are function variables to allow for mocking in tests.
	serviceNew     = service.New
	serviceControl = service.Control

	// newFilter creates the filter instance. It's a variable for mocking.
	newFilter = func(configFile, listenAddr string) (lib.Proxy, error) {
		return lib.NewDNSFilter(configFile, listenAddr)
	}
)

var serviceConfig = &service.Config{
	Name:        "dns-filter",
	DisplayName: "dns-filter",
	Description: "This is a DNS-Server that filters malware, porn and ads.",
	UserName:    "dnsfilter",
	Arguments:   []string{"-configFile", "/etc/dnsfilter.yml"},
}

func main() {
	// main is the untestable entry point. All logic is in runMain.
	if err := runMain(os.Args[1:]); err != nil {
		slog.Error("fatal error", err)
		os.Exit(1)
	}
}

// runMain contains the core logic of the main function and is testable.
func runMain(args []string) error {
	flags := flag.NewFlagSet("dnsfilter", flag.ExitOnError)
	configFile := flags.String("configFile", "", "Provide a yaml file.")
	listenAddr := flags.String("listenAddress", "", "sample: 127.0.0.1:5300, this overrides the one in the config")
	svcFlag := flags.String("service", "", "Control the system service.")
	wgFlag := flags.Bool("wg", false, "Set to true to require wg-quick@wg0.service")

	if err := flags.Parse(args); err != nil {
		return err
	}

	if *wgFlag {
		serviceConfig.Dependencies = []string{"After=network-online.target", "After=wg-quick@wg0.service", "Requires=wg-quick@wg0.service"}
	} else {
		serviceConfig.Dependencies = []string{"After=network-online.target"}
	}

	prg := &program{
		configFile: *configFile,
		listenAddr: *listenAddr,
	}
	s, err := serviceNew(prg, serviceConfig)
	if err != nil {
		return err
	}

	if len(*svcFlag) != 0 {
		err := serviceControl(s, *svcFlag)
		if err != nil {
			return err
		}
		// Successfully controlled the service, so we can exit.
		return nil
	}

	return s.Run()
}

type program struct {
	configFile string
	listenAddr string
}

func (p *program) Start(s service.Service) error {
	// Start should not block. Do the actual work async.
	go p.run()
	return nil
}

func (p *program) run() {
	dns, err := newFilter(p.configFile, p.listenAddr)
	if err != nil {
		slog.Error("dnsfilter", err)
		return
	}
	if err = dns.Run(); err != nil {
		slog.Error("dnsfilter", err)
	}
}

func (p *program) Stop(s service.Service) error {
	// Stop should not block. Return with a few seconds.
	return nil
}
