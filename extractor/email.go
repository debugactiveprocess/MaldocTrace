package extractor

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"path"
	"strings"
	"unicode/utf16"
)

// Email is a parsed message: headers, decoded bodies and attachments.
// Attachments are analysed by the caller like any other input.
type Email struct {
	From, To, Subject, Date string
	MessageID               string
	// Bodies are the decoded text and HTML bodies (URLs are taken from them).
	Bodies      []string
	Attachments []EmailAttachment
	Diagnostics []Diagnostic
	LimitsHit   []string
}

// EmailAttachment is one attached file (or attached message).
type EmailAttachment struct {
	Name        string
	ContentType string
	Data        []byte
}

const (
	maxEmailParts      = 256
	maxEmailDepth      = 10
	maxEmailAttachment = 64 << 20
	maxEmailBody       = 4 << 20
)

func (e *Email) diag(sev, msg string) {
	e.Diagnostics = append(e.Diagnostics, Diagnostic{Severity: sev, Stage: "email", Message: msg})
}

var emailHeaders = []string{"from:", "to:", "subject:", "date:", "received:", "mime-version:", "message-id:", "return-path:", "x-mailer:", "content-type:", "delivered-to:", "reply-to:"}

// looksLikeEmail reports an RFC 5322 message: the first lines are header
// fields and at least three of them are typical message headers.
func looksLikeEmail(data []byte) bool {
	head := data
	if len(head) > 16384 {
		head = head[:16384]
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return false
	}
	sc := bufio.NewScanner(bytes.NewReader(head))
	sc.Buffer(make([]byte, 0, 4096), 16384)
	known, lines := 0, 0
	for sc.Scan() {
		line := sc.Text()
		if lines == 0 && strings.HasPrefix(line, "From ") { // mbox separator
			lines++
			continue
		}
		if line == "" {
			break
		}
		lines++
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		i := strings.IndexByte(line, ':')
		if i <= 0 || strings.ContainsAny(line[:i], " \t") {
			return false
		}
		low := strings.ToLower(line[:i+1])
		for _, h := range emailHeaders {
			if low == h {
				known++
			}
		}
		if lines > 400 {
			break
		}
	}
	return known >= 3
}

var wordDecoder = &mime.WordDecoder{CharsetReader: func(charset string, in io.Reader) (io.Reader, error) {
	// Text in unknown charsets is kept as raw bytes.
	return in, nil
}}

func decodeHeader(s string) string {
	if d, err := wordDecoder.DecodeHeader(s); err == nil {
		return d
	}
	return s
}

// ParseEML parses an RFC 5322 / MIME message.
func ParseEML(data []byte) (*Email, error) {
	if bytes.HasPrefix(data, []byte("From ")) {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		}
	}
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return nil, Wrap("eml", err)
	}
	e := &Email{
		From:      decodeHeader(msg.Header.Get("From")),
		To:        decodeHeader(msg.Header.Get("To")),
		Subject:   decodeHeader(msg.Header.Get("Subject")),
		Date:      msg.Header.Get("Date"),
		MessageID: msg.Header.Get("Message-Id"),
	}
	body, _ := io.ReadAll(io.LimitReader(msg.Body, int64(len(data))))
	parts := 0
	e.walk(textproto(msg.Header), body, 0, &parts)
	return e, nil
}

type header interface{ Get(string) string }

type textproto mail.Header

func (h textproto) Get(k string) string { return mail.Header(h).Get(k) }

// decodeBody applies the Content-Transfer-Encoding.
func decodeBody(enc string, b []byte) []byte {
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "base64":
		clean := make([]byte, 0, len(b))
		for _, c := range b {
			if c > ' ' {
				clean = append(clean, c)
			}
		}
		for len(clean)%4 != 0 && len(clean) > 0 && clean[len(clean)-1] != '=' {
			clean = clean[:len(clean)-1]
		}
		out := make([]byte, base64.StdEncoding.DecodedLen(len(clean)))
		n, err := base64.StdEncoding.Decode(out, clean)
		if err != nil && n == 0 {
			if out2, err2 := base64.RawStdEncoding.DecodeString(strings.TrimRight(string(clean), "=")); err2 == nil {
				return out2
			}
		}
		return out[:n]
	case "quoted-printable":
		out, _ := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(b)))
		return out
	}
	return b
}

func (e *Email) walk(h header, body []byte, depth int, parts *int) {
	*parts++
	if *parts > maxEmailParts {
		if *parts == maxEmailParts+1 {
			e.LimitsHit = append(e.LimitsHit, "MaxEmailParts")
			e.diag("warning", fmt.Sprintf("more than %d MIME parts; the rest were not read", maxEmailParts))
		}
		return
	}
	if depth > maxEmailDepth {
		e.LimitsHit = append(e.LimitsHit, "MaxEmailDepth")
		e.diag("warning", "MIME nesting too deep")
		return
	}
	ctype := h.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(ctype)
	if err != nil {
		mediaType = "text/plain"
		if ctype != "" {
			mediaType = strings.ToLower(strings.TrimSpace(strings.SplitN(ctype, ";", 2)[0]))
		}
	}
	disp, dparams, _ := mime.ParseMediaType(h.Get("Content-Disposition"))
	name := decodeHeader(firstNonEmpty(dparams["filename"], params["name"]))
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			e.diag("warning", "multipart part without a boundary")
			return
		}
		mr := multipart.NewReader(bytes.NewReader(body), boundary)
		for {
			p, err := mr.NextRawPart()
			if err != nil {
				if err != io.EOF {
					e.diag("info", "MIME: "+err.Error())
				}
				return
			}
			b, _ := io.ReadAll(io.LimitReader(p, maxEmailAttachment+1))
			e.walk(p.Header, b, depth+1, parts)
			if *parts > maxEmailParts {
				return
			}
		}
	}
	data := decodeBody(h.Get("Content-Transfer-Encoding"), body)
	if mediaType == "message/rfc822" {
		e.Attachments = append(e.Attachments, EmailAttachment{Name: firstNonEmpty(name, "attached-message.eml"), ContentType: mediaType, Data: data})
		return
	}
	if name == "" && disp != "attachment" && (strings.HasPrefix(mediaType, "text/plain") || strings.HasPrefix(mediaType, "text/html")) {
		if len(data) > maxEmailBody {
			data = data[:maxEmailBody]
		}
		e.Bodies = append(e.Bodies, string(data))
		return
	}
	if len(data) > maxEmailAttachment {
		e.LimitsHit = append(e.LimitsHit, "MaxEmailAttachment")
		e.diag("warning", fmt.Sprintf("attachment %q over %d bytes not analysed", name, maxEmailAttachment))
		return
	}
	if name == "" {
		name = "part" + fmt.Sprint(*parts)
		if exts, _ := mime.ExtensionsByType(mediaType); len(exts) > 0 {
			name += exts[0]
		}
	}
	e.Attachments = append(e.Attachments, EmailAttachment{Name: path.Base(strings.ReplaceAll(name, `\`, "/")), ContentType: mediaType, Data: data})
}

// Outlook .msg ([MS-OXMSG]): a CFB with __properties_version1.0 and
// __substg1.0_<tag><type> streams; attachments in __attach_version1.0_#N
// storages; attached messages in their __substg1.0_3701000D storage.

func isOutlookMessage(data []byte) bool {
	cfb, err := parseCFB(data, &Limits{MaxContainerEntries: 1 << 16, MaxStreams: 1 << 14})
	if err != nil {
		return false
	}
	return cfb.find("__properties_version1.0") != nil && (cfb.find("__substg1.0_0037001F") != nil ||
		cfb.find("__substg1.0_0037001E") != nil || cfb.find("__substg1.0_1000001F") != nil ||
		len(cfb.storageByPrefix("__attach_version1.0_#")) > 0 || cfb.find("__substg1.0_001A001F") != nil)
}

func (r *cfbReader) storageByPrefix(prefix string) []*cfbEntry {
	var out []*cfbEntry
	for _, e := range r.entries {
		if e.objType == 1 && strings.HasPrefix(e.path, prefix) && !strings.Contains(e.path[len(prefix):], "/") {
			out = append(out, e)
		}
	}
	return out
}

// msgString reads a string property (Unicode 001F or 8-bit 001E).
func msgString(cfb *cfbReader, prefix, tag string) string {
	if b, err := cfb.readStream(prefix + "__substg1.0_" + tag + "001F"); err == nil {
		u := make([]uint16, len(b)/2)
		for i := range u {
			u[i] = binary.LittleEndian.Uint16(b[2*i:])
		}
		return strings.TrimRight(string(utf16.Decode(u)), "\x00")
	}
	if b, err := cfb.readStream(prefix + "__substg1.0_" + tag + "001E"); err == nil {
		return strings.TrimRight(string(b), "\x00")
	}
	return ""
}

// ParseMSG parses an Outlook message.
func ParseMSG(data []byte, lim *Limits) (*Email, error) {
	if lim == nil {
		l := DefaultLimits()
		lim = &l
	}
	cfb, err := parseCFB(data, lim)
	if err != nil {
		return nil, err
	}
	e := &Email{}
	e.readMSG(cfb, "", 0)
	return e, nil
}

func (e *Email) readMSG(cfb *cfbReader, prefix string, depth int) {
	subject := msgString(cfb, prefix, "0037")
	from := msgString(cfb, prefix, "0C1A")
	if addr := firstNonEmpty(msgString(cfb, prefix, "5D01"), msgString(cfb, prefix, "0C1F"), msgString(cfb, prefix, "0065")); addr != "" {
		if from != "" && from != addr {
			from += " <" + addr + ">"
		} else {
			from = addr
		}
	}
	if depth == 0 {
		e.Subject, e.From = subject, from
		e.To = msgString(cfb, prefix, "0E04")
		e.MessageID = msgString(cfb, prefix, "1035")
		if hdrs := msgString(cfb, prefix, "007D"); hdrs != "" {
			if m, err := mail.ReadMessage(strings.NewReader(hdrs + "\r\n\r\n")); err == nil {
				e.Date = m.Header.Get("Date")
				if e.From == "" {
					e.From = decodeHeader(m.Header.Get("From"))
				}
			}
		}
	} else {
		e.diag("info", fmt.Sprintf("attached message %q from %q", subject, from))
	}
	if body := msgString(cfb, prefix, "1000"); body != "" {
		e.Bodies = append(e.Bodies, body)
	}
	if html, err := cfb.readStream(prefix + "__substg1.0_10130102"); err == nil {
		e.Bodies = append(e.Bodies, string(html))
	} else if html := msgString(cfb, prefix, "1013"); html != "" {
		e.Bodies = append(e.Bodies, html)
	}
	for _, st := range cfb.storageByPrefix(prefix + "__attach_version1.0_#") {
		if len(e.Attachments) >= maxEmailParts {
			e.LimitsHit = append(e.LimitsHit, "MaxEmailParts")
			e.diag("warning", "too many attachments; the rest were not read")
			return
		}
		ap := st.path + "/"
		name := firstNonEmpty(msgString(cfb, ap, "3707"), msgString(cfb, ap, "3704"), msgString(cfb, ap, "3001"), path.Base(st.path))
		mimeTag := msgString(cfb, ap, "370E")
		if data, err := cfb.readStream(ap + "__substg1.0_37010102"); err == nil {
			if len(data) > maxEmailAttachment {
				e.LimitsHit = append(e.LimitsHit, "MaxEmailAttachment")
				e.diag("warning", fmt.Sprintf("attachment %q over %d bytes not analysed", name, maxEmailAttachment))
				continue
			}
			e.Attachments = append(e.Attachments, EmailAttachment{Name: path.Base(strings.ReplaceAll(name, `\`, "/")), ContentType: mimeTag, Data: data})
			continue
		}
		if sub := cfb.find(ap + "__substg1.0_3701000D"); sub != nil && sub.objType == 1 {
			if depth >= maxEmailDepth {
				e.LimitsHit = append(e.LimitsHit, "MaxEmailDepth")
				continue
			}
			before := len(e.Attachments)
			e.readMSG(cfb, ap+"__substg1.0_3701000D/", depth+1)
			for i := before; i < len(e.Attachments); i++ {
				e.Attachments[i].Name = name + "/" + e.Attachments[i].Name
			}
		}
	}
}
