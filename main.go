package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
)

const (
	socksVersion = 0x05

	methodNoAuth   = 0x00
	methodUserPass = 0x02
	methodNoAccept = 0xFF

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03

	repSuccess        = 0x00
	repGeneralFailure = 0x01
	repConnRefused    = 0x05
	repCmdUnsupported = 0x07
	repAddrUnsupported = 0x08
)

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	method, err := negotiateAuth(conn)
	if err != nil {
		log.Printf("auth negotiation error: %v", err)
		return
	}

	if method == methodUserPass {
		if err := authenticateUserPass(conn); err != nil {
			log.Printf("auth error: %v", err)
			return
		}
	}

	targetAddr, rep, err := readConnectRequest(conn)
	if err != nil {
		sendReply(conn, rep)
		log.Printf("connect request error: %v", err)
		return
	}

	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		sendReply(conn, repConnRefused)
		log.Printf("dial error: %v", err)
		return
	}
	defer target.Close()

	if err := sendReply(conn, repSuccess); err != nil {
		log.Printf("send reply error: %v", err)
		return
	}

	relay(conn, target)
}

func negotiateAuth(conn net.Conn) (byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, err
	}

	if header[0] != socksVersion {
		return 0, fmt.Errorf("unsupported SOCKS version")
	}

	nmethods := int(header[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, err
	}

	required := byte(methodNoAuth)
	if os.Getenv("PROXY_USER") != "" {
		required = methodUserPass
	}

	for _, m := range methods {
		if m == required {
			_, err := conn.Write([]byte{socksVersion, required})
			return required, err
		}
	}

	_, _ = conn.Write([]byte{socksVersion, methodNoAccept})
	return 0, fmt.Errorf("no acceptable auth method")
}

func authenticateUserPass(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	if header[0] != 0x01 {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("invalid auth version")
	}

	ulen := int(header[1])
	username := make([]byte, ulen)
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}

	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, plenBuf); err != nil {
		return err
	}

	plen := int(plenBuf[0])
	password := make([]byte, plen)
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}

	expectedUser := os.Getenv("PROXY_USER")
	expectedPass := os.Getenv("PROXY_PASS")

	if string(username) == expectedUser && string(password) == expectedPass {
		_, err := conn.Write([]byte{0x01, 0x00})
		return err
	}

	_, _ = conn.Write([]byte{0x01, 0x01})
	return fmt.Errorf("invalid username or password")
}

func readConnectRequest(conn net.Conn) (string, byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", repGeneralFailure, err
	}

	if header[0] != socksVersion {
		return "", repGeneralFailure, fmt.Errorf("invalid SOCKS version")
	}

	if header[1] != cmdConnect {
		return "", repCmdUnsupported, fmt.Errorf("unsupported command")
	}

	if header[2] != 0x00 {
		return "", repGeneralFailure, fmt.Errorf("invalid reserved byte")
	}

	atyp := header[3]
	var host string

	switch atyp {
	case atypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", repGeneralFailure, err
		}
		host = net.IP(addr).String()

	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", repGeneralFailure, err
		}

		domainLen := int(lenBuf[0])
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", repGeneralFailure, err
		}
		host = string(domain)

	default:
		return "", repAddrUnsupported, fmt.Errorf("unsupported address type")
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", repGeneralFailure, err
	}

	port := binary.BigEndian.Uint16(portBuf)
	return fmt.Sprintf("%s:%d", host, port), repSuccess, nil
}

func sendReply(conn net.Conn, rep byte) error {
	reply := []byte{
		socksVersion,
		rep,
		0x00,
		atypIPv4,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}

	_, err := conn.Write(reply)
	return err
}

func relay(client net.Conn, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(target, client)
		if tcp, ok := target.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, target)
		if tcp, ok := client.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()

	wg.Wait()
}