package main

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/dryaf/dnsfilter/lib"
	"github.com/kardianos/service"
)

// mockFilter implements the lib.Proxy interface for testing.
type mockFilter struct {
	runFunc   func() error
	runCalled chan struct{}
}

func (m *mockFilter) Run() error {
	if m.runCalled != nil {
		close(m.runCalled)
	}
	if m.runFunc != nil {
		return m.runFunc()
	}
	return nil
}

// mockService is a complete and correct implementation of the service.Service interface for testing.
type mockService struct {
	runFunc   func() error
	runCalled chan struct{}
}

// This struct now implements every method required by the service.Service interface.
func (m *mockService) Run() error {
	if m.runCalled != nil {
		close(m.runCalled)
	}
	if m.runFunc != nil {
		return m.runFunc()
	}
	return nil
}
func (m *mockService) Start() error   { return nil }
func (m *mockService) Stop() error    { return nil }
func (m *mockService) Restart() error { return nil }
func (m *mockService) Install() error { return nil }
func (m *mockService) Uninstall() error {
	return nil
}
func (m *mockService) Status() (service.Status, error) { return service.StatusUnknown, nil }
func (m *mockService) String() string                  { return "mockService" }
func (m *mockService) Platform() string                { return "mock" }
func (m *mockService) Logger(errs chan<- error) (service.Logger, error) {
	return nil, errors.New("not implemented")
}
func (m *mockService) SystemLogger(errs chan<- error) (service.Logger, error) {
	return nil, errors.New("not implemented")
}

func setupTestMain(t *testing.T) {
	t.Helper()
	// Keep original functions
	originalServiceNew := serviceNew
	originalServiceControl := serviceControl
	originalNewFilter := newFilter

	// Restore original functions after the test
	t.Cleanup(func() {
		serviceNew = originalServiceNew
		serviceControl = originalServiceControl
		newFilter = originalNewFilter
	})
}

func TestRunMain(t *testing.T) {
	setupTestMain(t)

	t.Run("runs as service", func(t *testing.T) {
		mockSvc := &mockService{runCalled: make(chan struct{})}
		serviceNew = func(p service.Interface, c *service.Config) (service.Service, error) {
			return mockSvc, nil
		}

		errCh := make(chan error, 1)
		go func() {
			errCh <- runMain([]string{"-configFile", "test.yml"})
		}()

		select {
		case <-mockSvc.runCalled:
			// Success
		case err := <-errCh:
			t.Fatalf("runMain exited unexpectedly with error: %v", err)
		case <-time.After(100 * time.Millisecond):
			t.Fatal("timed out waiting for service.Run to be called")
		}
	})

	t.Run("controls service with install flag", func(t *testing.T) {
		mockSvc := &mockService{}
		controlCalled := make(chan string)

		serviceNew = func(p service.Interface, c *service.Config) (service.Service, error) {
			return mockSvc, nil
		}
		serviceControl = func(s service.Service, action string) error {
			close(controlCalled)
			if action != "install" {
				return errors.New("expected action 'install'")
			}
			return nil
		}

		if err := runMain([]string{"-service", "install"}); err != nil {
			t.Fatalf("runMain returned an error: %v", err)
		}

		select {
		case <-controlCalled:
			// Success
		case <-time.After(100 * time.Millisecond):
			t.Fatal("timed out waiting for service.Control to be called")
		}
	})

	t.Run("sets wg dependencies", func(t *testing.T) {
		serviceNew = func(p service.Interface, c *service.Config) (service.Service, error) {
			// Check that the config was modified before creating the service
			if len(c.Dependencies) != 3 {
				t.Fatalf("expected 3 dependencies with -wg flag, got %d", len(c.Dependencies))
			}
			if c.Dependencies[2] != "Requires=wg-quick@wg0.service" {
				t.Errorf("unexpected dependency: %s", c.Dependencies[2])
			}
			return &mockService{runCalled: make(chan struct{})}, nil
		}

		// Run in a goroutine because it blocks on s.Run()
		go func() { _ = runMain([]string{"-wg"}) }()
	})

	t.Run("handles service.New error", func(t *testing.T) {
		expectedErr := errors.New("service new failed")
		serviceNew = func(p service.Interface, c *service.Config) (service.Service, error) {
			return nil, expectedErr
		}

		err := runMain([]string{})
		if !errors.Is(err, expectedErr) {
			t.Errorf("expected error '%v', got '%v'", expectedErr, err)
		}
	})

	t.Run("handles service.Control error", func(t *testing.T) {
		expectedErr := errors.New("service control failed")
		serviceNew = func(p service.Interface, c *service.Config) (service.Service, error) {
			return &mockService{}, nil
		}
		serviceControl = func(s service.Service, action string) error {
			return expectedErr
		}

		err := runMain([]string{"-service", "start"})
		if !errors.Is(err, expectedErr) {
			t.Errorf("expected error '%v', got '%v'", expectedErr, err)
		}
	})
}

func TestProgramStartAndStop(t *testing.T) {
	setupTestMain(t)
	var wg sync.WaitGroup
	wg.Add(1)

	mockFlt := &mockFilter{
		runFunc: func() error {
			wg.Done() // Signal that run has started
			return nil
		},
	}
	newFilter = func(configFile, listenAddr string) (lib.Proxy, error) {
		return mockFlt, nil
	}

	p := &program{}
	if err := p.Start(nil); err != nil {
		t.Fatalf("p.Start() returned an error: %v", err)
	}

	waitCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitCh)
	}()

	select {
	case <-waitCh:
		// test passed
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for program.run to be called")
	}

	if err := p.Stop(nil); err != nil {
		t.Fatalf("p.Stop() returned an error: %v", err)
	}
}
