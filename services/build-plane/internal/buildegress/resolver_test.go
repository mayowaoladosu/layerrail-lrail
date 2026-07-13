package buildegress

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestParseDNSResponseFollowsOnlyRelatedCNAMEs(t *testing.T) {
	t.Parallel()
	question := dnsQuestion(t, "packages.example.invalid", dnsmessage.TypeA)
	target := dnsName(t, "cdn.example.invalid")
	response := packDNSMessage(t, dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 7, Response: true, RecursionAvailable: true},
		Questions: []dnsmessage.Question{question},
		Answers: []dnsmessage.Resource{
			{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}, Body: &dnsmessage.CNAMEResource{CNAME: target}},
			{Header: dnsmessage.ResourceHeader{Name: target, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}}},
		},
	})
	addresses, err := parseDNSResponse(response, 7, question)
	if err != nil || !slices.Equal(addresses, []netip.Addr{netip.MustParseAddr("93.184.216.34")}) {
		t.Fatalf("addresses=%#v error=%v", addresses, err)
	}

	unrelated := dnsName(t, "poison.example.invalid")
	response = packDNSMessage(t, dnsmessage.Message{
		Header: dnsmessage.Header{ID: 7, Response: true}, Questions: []dnsmessage.Question{question},
		Answers: []dnsmessage.Resource{
			{Header: dnsmessage.ResourceHeader{Name: unrelated, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{10, 0, 0, 1}}},
		},
	})
	if _, err := parseDNSResponse(response, 7, question); err == nil {
		t.Fatal("expected unrelated address rejection")
	}
}

func TestParseDNSResponseRejectsIdentityFailureAndCNAMECycle(t *testing.T) {
	t.Parallel()
	question := dnsQuestion(t, "packages.example.invalid", dnsmessage.TypeA)
	other := dnsName(t, "other.example.invalid")
	cycle := packDNSMessage(t, dnsmessage.Message{
		Header: dnsmessage.Header{ID: 7, Response: true}, Questions: []dnsmessage.Question{question},
		Answers: []dnsmessage.Resource{
			{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}, Body: &dnsmessage.CNAMEResource{CNAME: other}},
			{Header: dnsmessage.ResourceHeader{Name: other, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}, Body: &dnsmessage.CNAMEResource{CNAME: question.Name}},
		},
	})
	if _, err := parseDNSResponse(cycle, 7, question); err == nil {
		t.Fatal("expected CNAME cycle rejection")
	}
	wrongID := packDNSMessage(t, dnsmessage.Message{Header: dnsmessage.Header{ID: 8, Response: true}, Questions: []dnsmessage.Question{question}})
	if _, err := parseDNSResponse(wrongID, 7, question); err == nil {
		t.Fatal("expected DNS transaction identity rejection")
	}
	failure := packDNSMessage(t, dnsmessage.Message{Header: dnsmessage.Header{ID: 7, Response: true, RCode: dnsmessage.RCodeServerFailure}, Questions: []dnsmessage.Question{question}})
	if _, err := parseDNSResponse(failure, 7, question); err == nil {
		t.Fatal("expected DNS failure rejection")
	}
	wrongQuestion := dnsQuestion(t, "attacker.example.invalid", dnsmessage.TypeA)
	spoofedNX := packDNSMessage(t, dnsmessage.Message{Header: dnsmessage.Header{ID: 7, Response: true, RCode: dnsmessage.RCodeNameError}, Questions: []dnsmessage.Question{wrongQuestion}})
	if _, err := parseDNSResponse(spoofedNX, 7, question); err == nil {
		t.Fatal("expected spoofed NXDOMAIN question rejection")
	}
}

func TestDNSResolverQueriesAAndAAAAAndFallsBackToTCP(t *testing.T) {
	t.Parallel()
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen TCP: %v", err)
	}
	defer tcpListener.Close()
	port := tcpListener.Addr().(*net.TCPAddr).Port
	udpConnection, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", stringPort(port)))
	if err != nil {
		t.Fatalf("Listen UDP: %v", err)
	}
	defer udpConnection.Close()
	serverErrors := make(chan error, 2)
	go serveUDPQueries(udpConnection, serverErrors)
	go serveTCPQuery(tcpListener, serverErrors)

	resolver := &DNSResolver{address: net.JoinHostPort("127.0.0.1", stringPort(port)), dialer: &net.Dialer{Timeout: time.Second}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addresses, err := resolver.LookupNetIP(ctx, "ip", "packages.example.invalid")
	if err != nil {
		t.Fatalf("LookupNetIP: %v", err)
	}
	expected := []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("2001:4860:4860::8888")}
	slices.SortFunc(expected, func(left, right netip.Addr) int { return left.Compare(right) })
	if !slices.Equal(addresses, expected) {
		t.Fatalf("addresses=%#v expected=%#v", addresses, expected)
	}
	for range 2 {
		if err := <-serverErrors; err != nil {
			t.Fatalf("DNS server: %v", err)
		}
	}
}

func serveUDPQueries(connection net.PacketConn, done chan<- error) {
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	for range 2 {
		buffer := make([]byte, maxDNSMessageBytes)
		count, peer, err := connection.ReadFrom(buffer)
		if err != nil {
			done <- err
			return
		}
		header, question, err := unpackDNSQuery(buffer[:count])
		if err != nil {
			done <- err
			return
		}
		message := dnsmessage.Message{Header: dnsmessage.Header{ID: header.ID, Response: true, RecursionAvailable: true}, Questions: []dnsmessage.Question{question}}
		if question.Type == dnsmessage.TypeA {
			message.Header.Truncated = true
		} else {
			message.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET},
				Body:   &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:4860:4860::8888").As16()},
			}}
		}
		response, err := message.Pack()
		if err != nil {
			done <- err
			return
		}
		if _, err := connection.WriteTo(response, peer); err != nil {
			done <- err
			return
		}
	}
	done <- nil
}

func serveTCPQuery(listener net.Listener, done chan<- error) {
	connection, err := listener.Accept()
	if err != nil {
		done <- err
		return
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	var lengthBytes [2]byte
	if _, err := io.ReadFull(connection, lengthBytes[:]); err != nil {
		done <- err
		return
	}
	query := make([]byte, int(binary.BigEndian.Uint16(lengthBytes[:])))
	if _, err := io.ReadFull(connection, query); err != nil {
		done <- err
		return
	}
	header, question, err := unpackDNSQuery(query)
	if err != nil {
		done <- err
		return
	}
	if question.Type != dnsmessage.TypeA {
		done <- errors.New("TCP fallback did not carry A question")
		return
	}
	message := dnsmessage.Message{
		Header: dnsmessage.Header{ID: header.ID, Response: true, RecursionAvailable: true}, Questions: []dnsmessage.Question{question},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
			Body:   &dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}},
		}},
	}
	response, err := message.Pack()
	if err != nil {
		done <- err
		return
	}
	framed := make([]byte, 2+len(response))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(response)))
	copy(framed[2:], response)
	done <- writeAll(connection, framed)
}

func unpackDNSQuery(contents []byte) (dnsmessage.Header, dnsmessage.Question, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(contents)
	if err != nil {
		return dnsmessage.Header{}, dnsmessage.Question{}, err
	}
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) != 1 {
		return dnsmessage.Header{}, dnsmessage.Question{}, errors.New("query question is invalid")
	}
	return header, questions[0], nil
}

func dnsQuestion(t *testing.T, host string, recordType dnsmessage.Type) dnsmessage.Question {
	t.Helper()
	return dnsmessage.Question{Name: dnsName(t, host), Type: recordType, Class: dnsmessage.ClassINET}
}

func dnsName(t *testing.T, host string) dnsmessage.Name {
	t.Helper()
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		t.Fatalf("NewName: %v", err)
	}
	return name
}

func packDNSMessage(t *testing.T, message dnsmessage.Message) []byte {
	t.Helper()
	contents, err := message.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	return contents
}

func stringPort(port int) string {
	return strconv.Itoa(port)
}
