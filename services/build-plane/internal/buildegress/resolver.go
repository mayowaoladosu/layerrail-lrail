package buildegress

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const maxDNSMessageBytes = 64 << 10
const maxDNSAnswers = 128
const maxCNAMEChain = 16
const dnsQueryTimeout = 5 * time.Second

// DNSResolver talks directly to one literal, site-owned DNS endpoint. It does
// not consult NSS, /etc/hosts, search domains, or ambient resolver settings.
type DNSResolver struct {
	address string
	dialer  *net.Dialer
}

// NewResolver returns a resolver pinned to one literal private cluster DNS
// endpoint. Both A and AAAA are queried afresh for every CONNECT.
func NewResolver(dnsAddress string) (*DNSResolver, error) {
	host, port, err := net.SplitHostPort(dnsAddress)
	portNumber, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || portErr != nil || portNumber == 0 {
		return nil, errors.New("egress DNS endpoint must contain a literal address and port")
	}
	address, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil || !address.IsValid() || !address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsUnspecified() || address.IsMulticast() {
		return nil, errors.New("egress DNS endpoint address is invalid")
	}
	return &DNSResolver{address: net.JoinHostPort(address.String(), strconv.FormatUint(portNumber, 10)), dialer: &net.Dialer{Timeout: dnsQueryTimeout}}, nil
}

func (resolver *DNSResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if resolver == nil || resolver.dialer == nil || ctx == nil || network != "ip" || !validHostname(host) {
		return nil, errors.New("egress DNS query is invalid")
	}
	type result struct {
		addresses []netip.Addr
		err       error
	}
	results := make(chan result, 2)
	for _, recordType := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		go func() {
			addresses, err := resolver.query(ctx, host, recordType)
			results <- result{addresses: addresses, err: err}
		}()
	}
	addresses := make(map[netip.Addr]struct{})
	for range 2 {
		result := <-results
		if result.err != nil {
			return nil, result.err
		}
		for _, address := range result.addresses {
			addresses[address.Unmap()] = struct{}{}
		}
	}
	if len(addresses) == 0 || len(addresses) > MaxResolvedAddresses {
		return nil, errors.New("egress DNS returned no or too many addresses")
	}
	resolved := make([]netip.Addr, 0, len(addresses))
	for address := range addresses {
		resolved = append(resolved, address)
	}
	slices.SortFunc(resolved, func(left, right netip.Addr) int { return left.Compare(right) })
	return resolved, nil
}

func (resolver *DNSResolver) query(ctx context.Context, host string, recordType dnsmessage.Type) ([]netip.Addr, error) {
	query, identifier, question, err := buildDNSQuery(host, recordType)
	if err != nil {
		return nil, err
	}
	response, truncated, err := resolver.exchange(ctx, "udp", query)
	if err != nil {
		return nil, err
	}
	if truncated {
		if err := validateTruncatedDNSResponse(response, identifier, question); err != nil {
			return nil, err
		}
		response, _, err = resolver.exchange(ctx, "tcp", query)
		if err != nil {
			return nil, err
		}
	}
	return parseDNSResponse(response, identifier, question)
}

func buildDNSQuery(host string, recordType dnsmessage.Type) ([]byte, uint16, dnsmessage.Question, error) {
	var identifierBytes [2]byte
	if _, err := rand.Read(identifierBytes[:]); err != nil {
		return nil, 0, dnsmessage.Question{}, errors.New("generate DNS query identifier")
	}
	identifier := binary.BigEndian.Uint16(identifierBytes[:])
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return nil, 0, dnsmessage.Question{}, errors.New("encode DNS query name")
	}
	question := dnsmessage.Question{Name: name, Type: recordType, Class: dnsmessage.ClassINET}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: identifier, RecursionDesired: true})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, 0, dnsmessage.Question{}, errors.New("start DNS query")
	}
	if err := builder.Question(question); err != nil {
		return nil, 0, dnsmessage.Question{}, errors.New("append DNS question")
	}
	query, err := builder.Finish()
	if err != nil {
		return nil, 0, dnsmessage.Question{}, errors.New("finish DNS query")
	}
	return query, identifier, question, nil
}

func (resolver *DNSResolver) exchange(ctx context.Context, network string, query []byte) ([]byte, bool, error) {
	connection, err := resolver.dialer.DialContext(ctx, network, resolver.address)
	if err != nil {
		return nil, false, errors.New("connect to trusted DNS")
	}
	defer connection.Close()
	deadline := time.Now().Add(dnsQueryTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, false, errors.New("set trusted DNS deadline")
	}
	if network == "tcp" {
		framed := make([]byte, 2+len(query))
		binary.BigEndian.PutUint16(framed[:2], uint16(len(query)))
		copy(framed[2:], query)
		if err := writeAll(connection, framed); err != nil {
			return nil, false, errors.New("write trusted DNS TCP query")
		}
		var lengthBytes [2]byte
		if _, err := io.ReadFull(connection, lengthBytes[:]); err != nil {
			return nil, false, errors.New("read trusted DNS TCP length")
		}
		length := int(binary.BigEndian.Uint16(lengthBytes[:]))
		if length < 12 || length > maxDNSMessageBytes {
			return nil, false, errors.New("trusted DNS TCP response size is invalid")
		}
		response := make([]byte, length)
		if _, err := io.ReadFull(connection, response); err != nil {
			return nil, false, errors.New("read trusted DNS TCP response")
		}
		header, err := peekDNSHeader(response)
		return response, header.Truncated, err
	}
	if err := writeAll(connection, query); err != nil {
		return nil, false, errors.New("write trusted DNS UDP query")
	}
	response := make([]byte, maxDNSMessageBytes)
	count, err := connection.Read(response)
	if err != nil || count < 12 {
		return nil, false, errors.New("read trusted DNS UDP response")
	}
	response = response[:count]
	header, err := peekDNSHeader(response)
	return response, header.Truncated, err
}

func peekDNSHeader(response []byte) (dnsmessage.Header, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(response)
	if err != nil {
		return dnsmessage.Header{}, errors.New("parse trusted DNS header")
	}
	return header, nil
}

func parseDNSResponse(response []byte, identifier uint16, question dnsmessage.Question) ([]netip.Addr, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(response)
	if err != nil || !header.Response || header.ID != identifier || header.OpCode != 0 || header.Truncated {
		return nil, errors.New("trusted DNS response header is invalid")
	}
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) != 1 || questions[0] != question {
		return nil, errors.New("trusted DNS response question differs")
	}
	if header.RCode == dnsmessage.RCodeNameError {
		return []netip.Addr{}, nil
	}
	if header.RCode != dnsmessage.RCodeSuccess {
		return nil, errors.New("trusted DNS response failed")
	}
	answers, err := parser.AllAnswers()
	if err != nil || len(answers) > maxDNSAnswers {
		return nil, errors.New("trusted DNS answer set is invalid")
	}
	aliases := make(map[string]string)
	type addressAnswer struct {
		name    string
		address netip.Addr
	}
	addressAnswers := make([]addressAnswer, 0, len(answers))
	for _, answer := range answers {
		if answer.Header.Class != dnsmessage.ClassINET {
			return nil, errors.New("trusted DNS answer class is invalid")
		}
		name, validName := canonicalDNSName(answer.Header.Name.String())
		if !validName {
			return nil, errors.New("trusted DNS answer name is invalid")
		}
		switch body := answer.Body.(type) {
		case *dnsmessage.CNAMEResource:
			target, validTarget := canonicalDNSName(body.CNAME.String())
			if !validTarget {
				return nil, errors.New("trusted DNS alias target is invalid")
			}
			if existing, duplicate := aliases[name]; duplicate && existing != target {
				return nil, errors.New("trusted DNS returned conflicting aliases")
			}
			aliases[name] = target
		case *dnsmessage.AResource:
			addressAnswers = append(addressAnswers, addressAnswer{name: name, address: netip.AddrFrom4(body.A)})
		case *dnsmessage.AAAAResource:
			addressAnswers = append(addressAnswers, addressAnswer{name: name, address: netip.AddrFrom16(body.AAAA)})
		}
	}
	questionName, validQuestion := canonicalDNSName(question.Name.String())
	if !validQuestion {
		return nil, errors.New("trusted DNS question name is invalid")
	}
	allowedNames := map[string]struct{}{questionName: {}}
	current := questionName
	for range maxCNAMEChain {
		target, exists := aliases[current]
		if !exists {
			break
		}
		if _, cycle := allowedNames[target]; cycle {
			return nil, errors.New("trusted DNS returned a CNAME cycle")
		}
		allowedNames[target] = struct{}{}
		current = target
	}
	if _, stillContinues := aliases[current]; stillContinues {
		return nil, errors.New("trusted DNS CNAME chain exceeds limit")
	}
	for alias := range aliases {
		if _, allowed := allowedNames[alias]; !allowed {
			return nil, errors.New("trusted DNS returned an unrelated alias")
		}
	}
	addresses := make([]netip.Addr, 0, len(addressAnswers))
	for _, answer := range addressAnswers {
		if answer.name != current || !answer.address.IsValid() {
			return nil, errors.New("trusted DNS returned a non-terminal address")
		}
		addresses = append(addresses, answer.address.Unmap())
	}
	return addresses, nil
}

func canonicalDNSName(value string) (string, bool) {
	value = strings.ToLower(value)
	if !strings.HasSuffix(value, ".") || strings.HasSuffix(value, "..") {
		return "", false
	}
	host := strings.TrimSuffix(value, ".")
	return host + ".", validHostname(host)
}

func validateTruncatedDNSResponse(response []byte, identifier uint16, question dnsmessage.Question) error {
	var parser dnsmessage.Parser
	header, err := parser.Start(response)
	if err != nil || !header.Response || !header.Truncated || header.ID != identifier || header.OpCode != 0 || header.RCode != dnsmessage.RCodeSuccess {
		return errors.New("truncated trusted DNS response header is invalid")
	}
	questions, err := parser.AllQuestions()
	if err != nil || len(questions) != 1 || questions[0] != question {
		return errors.New("truncated trusted DNS response question differs")
	}
	return nil
}

func writeAll(writer io.Writer, contents []byte) error {
	for len(contents) > 0 {
		written, err := writer.Write(contents)
		if err != nil || written <= 0 {
			return errors.New("short network write")
		}
		contents = contents[written:]
	}
	return nil
}

var _ Resolver = (*DNSResolver)(nil)
