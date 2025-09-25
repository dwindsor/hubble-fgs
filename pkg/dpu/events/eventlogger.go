package events

import (
	"encoding/json"
	"net"
	"sync"
	"time"
)

// NewEventLogger creates a new EventLogger instance
func NewEventLogger(socketPath string) *EventLogger {
	return &EventLogger{
		socketPath:    socketPath,
		timeout:       5 * time.Minute, // Default timeout of 5 minutes
		timeoutCancel: make(chan struct{}),
	}
}

// EventLogger represents a logger that writes to a Unix domain socket using UDP
type EventLogger struct {
	socketPath    string
	conn          *net.UnixConn
	mu            sync.Mutex
	connected     bool
	timeout       time.Duration
	lastActivity  time.Time
	timeoutTimer  *time.Timer
	timeoutCancel chan struct{}
}

// Connect establishes a connection to the Unix socket and locks the mutex
func (s *EventLogger) Connect() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connect()
}

// connect establishes a connection to the Unix socket (lock must be held)
func (s *EventLogger) connect() error {
	if s.connected {
		return nil
	}

	addr, err := net.ResolveUnixAddr("unixgram", s.socketPath)
	if err != nil {
		return err
	}

	conn, err := net.DialUnix("unixgram", nil, addr)
	if err != nil {
		return err
	}

	s.conn = conn
	s.connected = true
	s.lastActivity = time.Now()

	// Start timeout timer
	s.startTimeoutTimer()

	return nil
}

// startTimeoutTimer starts a timer that will close the connection after the timeout period
func (s *EventLogger) startTimeoutTimer() {
	// Stop and clean up any existing timer
	if s.timeoutTimer != nil {
		s.timeoutTimer.Stop()
		s.timeoutTimer = nil
	}

	// Close any existing cancel channel to prevent goroutine leaks
	if s.timeoutCancel != nil {
		close(s.timeoutCancel)
	}

	// Create a new cancel channel
	s.timeoutCancel = make(chan struct{})
	localCancel := s.timeoutCancel

	s.timeoutTimer = time.AfterFunc(s.timeout, func() {
		select {
		case <-localCancel:
			// Timer was cancelled
			return
		default:
			// Timer expired, close the connection
			s.mu.Lock()
			defer s.mu.Unlock()

			if s.connected && time.Since(s.lastActivity) >= s.timeout {
				s.closeConnection()
			}
		}
	})
}

// closeConnection closes the connection without locking (must be called with lock held)
func (s *EventLogger) closeConnection() {
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	s.connected = false
}

// Close closes the connection to the Unix socket
func (s *EventLogger) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.connected {
		return nil
	}

	// Cancel the timeout timer
	if s.timeoutTimer != nil {
		s.timeoutTimer.Stop()
		close(s.timeoutCancel)
	}

	s.closeConnection()
	return nil
}

// Log writes a message to the Unix socket, connecting if necessary
func (s *EventLogger) Log(message EventLogMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Connecting every time
	err := s.connect()
	if err != nil {
		return err
	}
	defer s.closeConnection()

	// Connect if not already connected
	// if !s.connected {
	// 	err := s.connect() // Already acquired locks, don't need to use Connect() function
	// 	if err != nil {
	// 		return err
	// 	}
	// }

	// // Update last activity time and timestamp
	// s.lastActivity = time.Now()
	// message.Timebuf = s.lastActivity.Format("2006-01-02T15:04:05.000Z")

	// // Reset the timeout timer
	// s.startTimeoutTimer()

	// Convert the message to JSON
	jsonMessage, err := json.Marshal(message)
	if err != nil {
		return err
	}

	// // Write the message
	// _, err = s.conn.Write(jsonMessage)
	// if err != nil {
	// 	// If there's an error writing, close the connection and return the error
	// 	s.closeConnection()
	// 	return err
	// }

	// Write the message
	_, err = s.conn.Write(jsonMessage)
	if err != nil {
		return err
	}

	return nil
}

// IsConnected returns whether the eventlogger is currently connected
func (s *EventLogger) IsConnected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connected
}
