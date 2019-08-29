package xmpp

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"github.com/pkg/errors"
	"net"
	"strings"
)

type Mechanism interface {
	Name() string
	DoAuth(*xml.Decoder, net.Conn) error
}

type PlainMechanism struct {
	user string
	pass string
}

func (p *PlainMechanism) Name() string {
	return "PLAIN"
}

func (p *PlainMechanism) DoAuth(_ *xml.Decoder, conn net.Conn) error {
	raw := "\x00" + p.user + "\x00" + p.pass
	enc := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(enc, []byte(raw))
	_, err := fmt.Fprintf(conn, "<auth xmlns='%s' mechanism='%s'>%s</auth>\n", nsSASL, p.Name(), enc)
	return err
}

type OAuthMechanism struct {
	user  string
	token string
	ns    string
}

func (o *OAuthMechanism) Name() string {
	return "X-OAUTH2"
}

func (o *OAuthMechanism) DoAuth(_ *xml.Decoder, conn net.Conn) error {
	raw := "\x00" + o.user + "\x00" + o.token
	enc := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(enc, []byte(raw))
	_, err := fmt.Fprintf(conn, "<auth xmlns='%s' mechanism='X-OAUTH2' auth:service='oauth2' "+
		"xmlns:auth='%s'>%s</auth>\n", nsSASL, o.ns, enc)
	return err
}

type MD5DigestMechanism struct {
	user     string
	domain   string
	password string
}

func (md *MD5DigestMechanism) Name() string {
	return "DIGEST-MD5"
}

func (md *MD5DigestMechanism) DoAuth(p *xml.Decoder, conn net.Conn) error {
	// Digest-MD5 authentication
	_, err := fmt.Fprintf(conn, "<auth xmlns='%s' mechanism='DIGEST-MD5'/>\n", nsSASL)
	if err != nil {
		return errors.Wrap(err, "failed to write init MD5Digest response")
	}
	var ch saslChallenge
	if err = p.DecodeElement(&ch, nil); err != nil {
		return errors.Wrap(err, "failed to unmarshal <challenge>")
	}
	b, err := base64.StdEncoding.DecodeString(string(ch))
	if err != nil {
		return err
	}
	tokens := map[string]string{}
	for _, token := range strings.Split(string(b), ",") {
		kv := strings.SplitN(strings.TrimSpace(token), "=", 2)
		if len(kv) == 2 {
			if kv[1][0] == '"' && kv[1][len(kv[1])-1] == '"' {
				kv[1] = kv[1][1 : len(kv[1])-1]
			}
			tokens[kv[0]] = kv[1]
		}
	}
	realm, _ := tokens["realm"]
	nonce, _ := tokens["nonce"]
	qop, _ := tokens["qop"]
	charset, _ := tokens["charset"]
	cnonceStr := cnonce()
	digestURI := "xmpp/" + md.domain
	nonceCount := fmt.Sprintf("%08x", 1)
	digest := saslDigestResponse(md.user, realm, md.password, nonce, cnonceStr, "AUTHENTICATE", digestURI, nonceCount)
	message := "username=\"" + md.user + "\", realm=\"" + realm + "\", nonce=\"" + nonce + "\", cnonce=\"" + cnonceStr +
		"\", nc=" + nonceCount + ", qop=" + qop + ", digest-uri=\"" + digestURI + "\", response=" + digest + ", charset=" + charset

	_, err = fmt.Fprintf(conn, "<response xmlns='%s'>%s</response>\n", nsSASL, base64.StdEncoding.EncodeToString([]byte(message)))
	if err != nil {
		return err
	}
	var rspauth saslRspAuth
	if err = p.DecodeElement(&rspauth, nil); err != nil {
		return errors.Wrap(err, "failed to unmarshal <challenge> (phase 2)")
	}
	b, err = base64.StdEncoding.DecodeString(string(rspauth))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(conn, "<response xmlns='%s'/>\n", nsSASL)
	return err
}

type AnonymousMechanism struct{}

func (anon *AnonymousMechanism) Name() string {
	return "ANONYMOUS"
}

func (anon *AnonymousMechanism) DoAuth(p *xml.Decoder, conn net.Conn) error {
	_, err := fmt.Fprintf(conn, "<auth xmlns='%s' mechanism='ANONYMOUS' />\n", nsSASL)
	return err
}
