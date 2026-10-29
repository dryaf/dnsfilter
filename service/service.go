package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kardianos/service"

	"github.com/dryaf/dnsfilter/lib"
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
		slog.Error("fatal error", "err", err)
		os.Exit(1)
	}
}

// runMain contains the core logic of the main function and is testable.
func runMain(args []string) error {
	flags := flag.NewFlagSet("dnsfilter", flag.ContinueOnError)
	configFile := flags.String("configFile", "", "Provide a yaml file.")
	listenAddr := flags.String("listenAddress", "", "sample: 127.0.0.1:5300, this overrides the one in the config")
	svcFlag := flags.String("service", "", "Control the system service.")
	wgFlag := flags.Bool("wg", false, "Set to true to require wg-quick@wg0.service")
	checkConfig := flags.Bool("checkConfig", false, "Validate configuration without starting listeners; print the listen address as JSON.")
	checkDNS := flags.String("checkDNS", "", "Check UDP and TCP DNS at this local address and exit.")

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if (*checkConfig && *checkDNS != "") || ((*checkConfig || *checkDNS != "") && *svcFlag != "") {
		return errors.New("configuration checks, DNS probes and service control cannot be combined")
	}
	if *checkConfig {
		return checkConfigFile(*configFile, *listenAddr)
	}
	if *checkDNS != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return lib.CheckDNS(ctx, *checkDNS)
	}

	config := *serviceConfig
	if *wgFlag {
		config.Dependencies = []string{"After=network-online.target", "After=wg-quick@wg0.service", "Requires=wg-quick@wg0.service"}
	} else {
		config.Dependencies = []string{"After=network-online.target"}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	prg := &program{
		configFile: *configFile,
		listenAddr: *listenAddr,
		ctx:        ctx,
	}
	// Linux service backends normally wait only for a signal. Also wake them
	// when DNS stops, so Stop can return its error to main and the supervisor.
	config.Option = service.KeyValue{"RunWait": prg.wait}
	s, err := serviceNew(prg, &config)
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

func checkConfigFile(configFile, listenAddr string) error {
	validated, err := lib.ConfigFromFile(configFile)
	if err != nil {
		return err
	}
	if listenAddr != "" {
		validated.ListenAddr = listenAddr
	}
	if err := validated.Validate(); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"listen_addr": validated.ListenAddr})
}

type program struct {
	configFile string
	listenAddr string
	ctx        context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	runErr     error
}

func (p *program) Start(s service.Service) error {
	filter, err := newFilter(p.configFile, p.listenAddr)
	if err != nil {
		return err
	}
	parent := p.ctx
	if parent == nil {
		parent = context.Background()
	}
	p.ctx, p.cancel = context.WithCancel(parent)
	p.done = make(chan struct{})
	go func() {
		p.runErr = filter.RunContext(p.ctx)
		if p.runErr == nil && p.ctx.Err() == nil {
			p.runErr = errors.New("DNS filter stopped unexpectedly")
		}
		close(p.done)
	}()
	return nil
}

func (p *program) wait() {
	select {
	case <-p.ctx.Done():
	case <-p.done:
	}
}

func (p *program) Stop(s service.Service) error {
	if p.cancel == nil {
		return nil
	}
	p.cancel()
	select {
	case <-p.done:
		return p.runErr
	case <-time.After(6 * time.Second):
		return errors.New("timed out stopping DNS filter")
	}
}
