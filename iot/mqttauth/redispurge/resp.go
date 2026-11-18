package redispurge

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	maxBulk  = 1 << 20
	maxArray = 16
)

// writeCommand encodes a command as a RESP array of bulk strings.
func writeCommand(w io.Writer, args ...string) error {
	var sb strings.Builder
	sb.WriteString("*" + strconv.Itoa(len(args)) + "\r\n")
	for _, a := range args {
		sb.WriteString("$" + strconv.Itoa(len(a)) + "\r\n" + a + "\r\n")
	}
	_, err := io.WriteString(w, sb.String())
	return err
}

// reply is one parsed RESP2 value. Only the shapes this package needs are kept.
type reply struct {
	kind  byte // '+', '-', ':', '$', '*'
	str   string
	items []reply
	nilv  bool
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return "", errors.New("redispurge: malformed line")
	}
	return line[:len(line)-2], nil
}

// readReply parses one RESP2 value with bounded sizes.
func readReply(r *bufio.Reader) (reply, error) {
	line, err := readLine(r)
	if err != nil {
		return reply{}, err
	}
	if line == "" {
		return reply{}, errors.New("redispurge: empty reply")
	}
	kind, rest := line[0], line[1:]
	switch kind {
	case '+', '-', ':':
		return reply{kind: kind, str: rest}, nil
	case '$':
		n, err := strconv.Atoi(rest)
		if err != nil || n < -1 || n > maxBulk {
			return reply{}, fmt.Errorf("redispurge: bad bulk length %q", rest)
		}
		if n == -1 {
			return reply{kind: kind, nilv: true}, nil
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return reply{}, err
		}
		if buf[n] != '\r' || buf[n+1] != '\n' {
			return reply{}, errors.New("redispurge: malformed bulk")
		}
		return reply{kind: kind, str: string(buf[:n])}, nil
	case '*':
		n, err := strconv.Atoi(rest)
		if err != nil || n < -1 || n > maxArray {
			return reply{}, fmt.Errorf("redispurge: bad array length %q", rest)
		}
		if n == -1 {
			return reply{kind: kind, nilv: true}, nil
		}
		out := reply{kind: kind, items: make([]reply, 0, n)}
		for i := 0; i < n; i++ {
			it, err := readReply(r)
			if err != nil {
				return reply{}, err
			}
			out.items = append(out.items, it)
		}
		return out, nil
	}
	return reply{}, fmt.Errorf("redispurge: unsupported reply type %q", kind)
}
