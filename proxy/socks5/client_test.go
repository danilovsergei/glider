package socks5

import (
	"bytes"
	"io"
	"net"
	"testing"

)

// mockDialer is a simple dialer that connects to our local test server
type mockDialer struct {
	addr string
}

func (m *mockDialer) Addr() string { return m.addr }
func (m *mockDialer) Dial(network, addr string) (net.Conn, error) {
	return net.Dial(network, m.addr) // route to mock server instead
}
func (m *mockDialer) DialUDP(network, addr string) (net.PacketConn, error) {
	return net.ListenPacket("udp", "127.0.0.1:0")
}
func (m *mockDialer) Close() error { return nil }

func TestUDPAssociateBindsUnspecifiedAddress(t *testing.T) {
	// 1. Start a mock SOCKS5 server to intercept the UDP Associate command
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	// 2. Set up the SOCKS5 client dialer
	dialer, err := NewSocks5Dialer("socks5://"+l.Addr().String(), &mockDialer{addr: l.Addr().String()})
	if err != nil {
		t.Fatalf("failed to create dialer: %v", err)
	}

	// 3. Handle the SOCKS5 handshake in a goroutine
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read Greeting (Method selection)
		buf := make([]byte, 256)
		_, err = io.ReadAtLeast(conn, buf, 2)
		if err != nil {
			t.Errorf("failed reading greeting: %v", err)
			return
		}

		// Reply No Auth
		conn.Write([]byte{0x05, 0x00})

		// Read UDP Associate Request
		// Format: VER (1) | CMD (1) | RSV (1) | ATYP (1) | DST.ADDR (var) | DST.PORT (2)
		_, err = io.ReadAtLeast(conn, buf, 10) // min 10 for IPv4
		if err != nil {
			t.Errorf("failed reading request: %v", err)
			return
		}

		if buf[1] != 0x03 { // CmdUDPAssociate is 3
			t.Errorf("expected UDP Associate (0x03), got %x", buf[1])
		}

		// We expect ATYP = 1 (IPv4) and IP = 0.0.0.0 and PORT = 0
		expected := []byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		if !bytes.Equal(buf[:10], expected) {
			t.Errorf("expected UDP Associate payload %x, got %x. The client is not requesting 0.0.0.0:0!", expected, buf[:10])
		}

		// Reply with success and a dummy bind address (127.0.0.1:12345)
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x30, 0x39})
	}()

	// 4. Trigger the DialUDP function
	// We want to connect to a specific target, but the SOCKS5 handshake
	// MUST request 0.0.0.0:0 regardless of this target.
	s := dialer.(*Socks5)
	_, err = s.DialUDP("udp", "8.8.8.8:53")
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
}
