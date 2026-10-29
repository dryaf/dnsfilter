package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kardianos/service"

	"github.com/dryaf/dnsfilter/lib"
)

type mockFilter struct{ runFunc func(context.Context) error }

func (m *mockFilter) RunContext(ctx context.Context) error { return m.runFunc(ctx) }

type mockService struct{ runFunc func() error }

func (m *mockService) Run() error {
	if m.runFunc != nil {
		return m.runFunc()
	}
	return nil
}
func (m *mockService) Start() error                    { return nil }
func (m *mockService) Stop() error                     { return nil }
func (m *mockService) Restart() error                  { return nil }
func (m *mockService) Install() error                  { return nil }
func (m *mockService) Uninstall() error                { return nil }
func (m *mockService) Status() (service.Status, error) { return service.StatusUnknown, nil }
func (m *mockService) String() string                  { return "mockService" }
func (m *mockService) Platform() string                { return "mock" }
func (m *mockService) Logger(chan<- error) (service.Logger, error) {
	return nil, errors.New("not implemented")
}
func (m *mockService) SystemLogger(chan<- error) (service.Logger, error) {
	return nil, errors.New("not implemented")
}

func setupTestMain(t *testing.T) {
	t.Helper()
	originalServiceNew, originalServiceControl, originalNewFilter := serviceNew, serviceControl, newFilter
	t.Cleanup(func() {
		serviceNew, serviceControl, newFilter = originalServiceNew, originalServiceControl, originalNewFilter
	})
}

func TestRunMain(t *testing.T) {
	t.Run("runs service synchronously", func(t *testing.T) {
		setupTestMain(t)
		called := false
		serviceNew = func(service.Interface, *service.Config) (service.Service, error) {
			return &mockService{runFunc: func() error { called = true; return nil }}, nil
		}
		if err := runMain([]string{"-configFile", "test.yml"}); err != nil {
			t.Fatal(err)
		}
		if !called {
			t.Fatal("service.Run was not called")
		}
	})
	t.Run("install needs no runtime configuration", func(t *testing.T) {
		setupTestMain(t)
		serviceNew = func(service.Interface, *service.Config) (service.Service, error) { return &mockService{}, nil }
		called := false
		serviceControl = func(_ service.Service, action string) error {
			called = true
			if action != "install" {
				t.Errorf("action=%s", action)
			}
			return nil
		}
		newFilter = func(string, string) (lib.Proxy, error) {
			t.Error("install initialized DNS")
			return nil, errors.New("unexpected call")
		}
		if err := runMain([]string{"-service", "install"}); err != nil {
			t.Fatal(err)
		}
		if !called {
			t.Fatal("service.Control was not called")
		}
	})
	t.Run("WireGuard dependencies do not leak between invocations", func(t *testing.T) {
		setupTestMain(t)
		want := 3
		serviceNew = func(_ service.Interface, config *service.Config) (service.Service, error) {
			if len(config.Dependencies) != want {
				t.Errorf("dependencies=%v, want %d", config.Dependencies, want)
			}
			if want == 3 && len(config.Dependencies) == 3 && config.Dependencies[2] != "Requires=wg-quick@wg0.service" {
				t.Error("missing WireGuard dependency")
			}
			return &mockService{}, nil
		}
		if err := runMain([]string{"-wg"}); err != nil {
			t.Fatal(err)
		}
		want = 1
		if err := runMain(nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("service construction error", func(t *testing.T) {
		setupTestMain(t)
		want := errors.New("service construction failed")
		serviceNew = func(service.Interface, *service.Config) (service.Service, error) { return nil, want }
		if err := runMain(nil); !errors.Is(err, want) {
			t.Fatalf("error=%v, want %v", err, want)
		}
	})
	t.Run("service control error", func(t *testing.T) {
		setupTestMain(t)
		want := errors.New("service control failed")
		serviceNew = func(service.Interface, *service.Config) (service.Service, error) { return &mockService{}, nil }
		serviceControl = func(service.Service, string) error { return want }
		if err := runMain([]string{"-service", "start"}); !errors.Is(err, want) {
			t.Fatalf("error=%v, want %v", err, want)
		}
	})
	t.Run("invalid flag returns an error", func(t *testing.T) {
		if err := runMain([]string{"-unknown"}); err == nil {
			t.Fatal("expected a flag error")
		}
	})
	t.Run("help exits successfully", func(t *testing.T) {
		if err := runMain([]string{"-h"}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRunMainPropagatesDNSErrors(t *testing.T) {
	for _, duringStartup := range []bool{true, false} {
		name := "listener failure"
		if duringStartup {
			name = "invalid configuration"
		}
		t.Run(name, func(t *testing.T) {
			setupTestMain(t)
			want := errors.New(name)
			newFilter = func(string, string) (lib.Proxy, error) {
				if duringStartup {
					return nil, want
				}
				return &mockFilter{runFunc: func(context.Context) error { return want }}, nil
			}
			serviceNew = func(p service.Interface, config *service.Config) (service.Service, error) {
				return &mockService{runFunc: func() error {
					if err := p.Start(nil); err != nil {
						return err
					}
					config.Option["RunWait"].(func())()
					return p.Stop(nil)
				}}, nil
			}
			done := make(chan error, 1)
			go func() { done <- runMain([]string{"-configFile", "test.yml"}) }()
			select {
			case err := <-done:
				if !errors.Is(err, want) {
					t.Fatalf("error=%v, want %v", err, want)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("DNS failure did not terminate the service")
			}
		})
	}
}

func TestProgramStopCancelsAndWaits(t *testing.T) {
	setupTestMain(t)
	started, stopped := make(chan struct{}), make(chan struct{})
	newFilter = func(string, string) (lib.Proxy, error) {
		return &mockFilter{runFunc: func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			close(stopped)
			return nil
		}}, nil
	}
	p := &program{}
	if err := p.Start(nil); err != nil {
		t.Fatal(err)
	}
	<-started
	if err := p.Stop(nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("Stop returned before DNS shut down")
	}
}

func TestProgramUnexpectedExitIsFailure(t *testing.T) {
	setupTestMain(t)
	newFilter = func(string, string) (lib.Proxy, error) {
		return &mockFilter{runFunc: func(context.Context) error { return nil }}, nil
	}
	p := &program{}
	if err := p.Start(nil); err != nil {
		t.Fatal(err)
	}
	p.wait()
	if err := p.Stop(nil); err == nil {
		t.Fatal("unexpected DNS exit must fail the service")
	}
}

func TestConfigurationCheckDoesNotStartService(t *testing.T) {
	setupTestMain(t)
	serviceNew = func(service.Interface, *service.Config) (service.Service, error) {
		t.Fatal("configuration check constructed a service")
		return nil, nil
	}
	newFilter = func(string, string) (lib.Proxy, error) {
		t.Fatal("configuration check initialized listeners or a cache")
		return nil, nil
	}
	for _, tc := range []struct {
		name, config string
		wantError    bool
	}{
		{"valid", "listen_addr: 127.0.0.1:53\nresolver_unfiltered:\n  addr: 127.0.0.1:853\n", false},
		{"missing resolver", "listen_addr: 127.0.0.1:53\n", true},
		{"malformed YAML", "listen_addr: [\n", true},
		{"duplicate setting", "listen_addr: 127.0.0.1:53\nlisten_addr: 127.0.0.1:54\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yml")
			if err := os.WriteFile(path, []byte(tc.config), 0600); err != nil {
				t.Fatal(err)
			}
			if err := runMain([]string{"-checkConfig", "-configFile", path}); (err != nil) != tc.wantError {
				t.Fatalf("checkConfig error=%v, wantError=%v", err, tc.wantError)
			}
		})
	}
	if err := runMain([]string{"-checkConfig", "-service", "restart"}); err == nil {
		t.Fatal("accepted conflicting validation and service control")
	}
}
