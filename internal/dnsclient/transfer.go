package dnsclient

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
)

const (
	// maxTransferMessage is the largest message this reads from a transfer.
	//
	// The resolver's own cap is the EDNS buffer size, which is the right
	// figure for one answer to one question and far too small here: a server
	// sending a zone fills messages to what TCP framing allows.
	maxTransferMessage = 65535

	// maxTransferBytes bounds a whole transfer.
	//
	// A server that keeps sending is a server this would keep reading, and
	// the memory it spends is chosen by whoever runs it rather than by
	// whoever asked. Eight megabytes is a very large zone; past it the
	// transfer is stopped and the caller is told it was cut.
	maxTransferBytes = 8 << 20

	// maxTransferRecords bounds the same thing by count, because a zone of a
	// million empty records is small in bytes and long in work.
	maxTransferRecords = 200000

	// maxTransferMessages bounds how many messages a transfer may take, so a
	// server sending empty ones forever is left rather than followed.
	maxTransferMessages = 4096
)

// Transfer asks one name server for a whole zone and returns the names in it.
//
// # What this is
//
// One question of type AXFR, over TCP, to a server the zone itself names. The
// answer is the zone as that server holds it: every name in it, from the
// server that is authoritative for them. There is nothing to guess and nothing
// to infer — which is why it is the best source of an estate's names when it
// is available, and why it usually is not.
//
// # What it does not do
//
// It does not follow the zone anywhere. A delegated subzone is a different
// zone with a different server, and its contents are its own question. It asks
// one server rather than every server the zone names: a transfer that
// succeeded once is the zone, and asking the rest again would be asking four
// servers for the same list.
//
// The names come back as the server wrote them, folded. Everything else about
// each record — its type, its data, its signatures — is read past without
// being kept: the question here is which names exist, and a record's contents
// belong to whatever asked for that record.
func (c *Client) Transfer(ctx context.Context, server, zone string) (names []string, truncated bool, err error) {
	question, err := encodeName(zone, false)
	if err != nil {
		return nil, false, fmt.Errorf("dnsclient: the zone name could not be encoded: %w", err)
	}

	// Recursion off. A name server asked directly is being asked what it
	// holds, and asking it to go and find out would be asking it to transfer
	// somebody else's zone.
	id, err := randomUint16()
	if err != nil {
		return nil, false, err
	}
	query := buildQueryWith(id, question, TypeAXFR, false)

	conn, err := c.dial(ctx, "tcp", withPort(server))
	if err != nil {
		return nil, false, fmt.Errorf("dnsclient: reaching the name server over TCP: %w", err)
	}
	defer conn.Close() //nolint:errcheck // the transfer is read or the error already returned

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if len(query) > maxTransferMessage {
		return nil, false, fmt.Errorf("dnsclient: the query is %d bytes", len(query))
	}
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed, uint16(len(query))) // #nosec G115 -- bounded a line above
	copy(framed[2:], query)

	if _, err := conn.Write(framed); err != nil {
		return nil, false, fmt.Errorf("dnsclient: sending the transfer request: %w", err)
	}

	var (
		read    int
		records int
		soas    int
	)

	for message := 0; ; message++ {
		if message >= maxTransferMessages {
			return names, true, nil
		}

		raw, err := readTransferMessage(conn, read)
		if err != nil {
			if len(names) > 0 {
				// A transfer that stopped part way through has already handed
				// over names, and they are names. Reporting nothing because
				// the end never came would throw away what the server did say
				// — but it is cut, and says so.
				return names, true, nil
			}
			return nil, false, err
		}
		read += len(raw)

		// The three ways a server says no, which every other caller of this
		// question already has to tell apart: REFUSED, NOTAUTH from a server
		// following RFC 8945, and NOTIMP from one without the query type.
		const (
			success = 0
			refused = 5
			notImp  = 4
			notAuth = 9
		)
		if code := rcodeOf(raw); code != success {
			if code == refused || code == notAuth || code == notImp {
				return nil, false, ErrNoTransfer
			}
			return nil, false, fmt.Errorf("dnsclient: the name server answered the transfer with code %d", code)
		}

		found, endings, err := transferNames(raw)
		if err != nil {
			return nil, false, err
		}
		records += len(found)
		soas += endings

		for _, name := range found {
			if len(names) >= maxTransferRecords {
				return names, true, nil
			}
			names = append(names, name)
		}

		// A transfer opens with the zone's SOA and closes with it again.
		// Anything after the second one is not part of this answer.
		if soas >= 2 {
			return names, false, nil
		}
		if read >= maxTransferBytes || records >= maxTransferRecords {
			return names, true, nil
		}
	}
}

// readTransferMessage reads one length-framed message of a transfer.
func readTransferMessage(conn net.Conn, alreadyRead int) ([]byte, error) {
	var length [2]byte
	if _, err := readFull(conn, length[:]); err != nil {
		return nil, fmt.Errorf("dnsclient: reading the transfer length: %w", err)
	}

	// The length is the server's, so it is checked rather than trusted: a
	// figure accepted as given is an allocation somebody else chose.
	size := int(binary.BigEndian.Uint16(length[:]))
	if size < headerLen {
		return nil, fmt.Errorf("dnsclient: a transfer message announces %d bytes", size)
	}
	if alreadyRead+size > maxTransferBytes {
		return nil, fmt.Errorf("dnsclient: the transfer is larger than %d bytes", maxTransferBytes)
	}

	raw := make([]byte, size)
	if _, err := readFull(conn, raw); err != nil {
		return nil, fmt.Errorf("dnsclient: reading a transfer message: %w", err)
	}
	return raw, nil
}

// rcodeOf reads the answer code out of a message header.
func rcodeOf(raw []byte) int {
	if len(raw) < headerLen {
		return -1
	}
	return int(binary.BigEndian.Uint16(raw[2:4]) & 0x000f)
}
