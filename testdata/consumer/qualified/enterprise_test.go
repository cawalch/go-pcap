package qualified_test

import (
	"io"
	"slices"
	"testing"

	pcap "github.com/cawalch/go-pcap"
)

func TestTaggedEnterpriseEvidence(t *testing.T) {
	const name = "enterprise-qualified.pcapng"
	_, data := fixture(t, name)
	capture, err := pcap.New(data)
	if err != nil {
		t.Fatal(err)
	}
	kerberos, err := capture.Kerberos(data)
	if err != nil || len(kerberos) != 1 || kerberos[0].PacketIndex != 0 ||
		kerberos[0].Message.Realm != "FIXTURE.EXAMPLE" || kerberos[0].Message.ErrorCode != 25 {
		t.Fatalf("Kerberos was not decoded as in the reference: %+v, %v", kerberos, err)
	}
	rdp, err := capture.RDP(data)
	if err != nil || len(rdp) != 1 || rdp[0].DstPort != 3389 ||
		rdp[0].Negotiation.Cookie != "mstshash=fixture" ||
		rdp[0].Negotiation.RequestedProtocols != pcap.RDPProtoTLS {
		t.Fatalf("RDP was not decoded as in the reference: %+v, %v", rdp, err)
	}
	ldap := verifyInputs(t, name, (*pcap.Capture).LDAP, (*pcap.Capture).LDAPFromReaderAt)
	if len(ldap) != 1 || ldap[0].PacketIndex != 6 || ldap[0].Message.BindDN != "cn=reader" {
		t.Fatalf("LDAP was not decoded as in the reference: %+v", ldap)
	}
	rpc := verifyInputs(t, name, (*pcap.Capture).DCERPC, (*pcap.Capture).DCERPCFromReaderAt)
	if len(rpc) != 1 || rpc[0].PacketIndex != 9 || rpc[0].Message.PacketType != pcap.DCERPCBind ||
		len(rpc[0].Message.Contexts) != 1 ||
		rpc[0].Message.Contexts[0].AbstractSyntaxUUID != "e1af8308-5d1f-11c9-91a4-08002b14a0fa" {
		t.Fatalf("DCE/RPC was not decoded as in the reference: %+v", rpc)
	}
	ldaps := verifyInputs(t, name,
		func(c *pcap.Capture, data []byte) ([]pcap.KeyedLDAPRecord, error) { return c.KeyedLDAP(data, nil) },
		func(c *pcap.Capture, r io.ReaderAt) ([]pcap.KeyedLDAPRecord, error) {
			return c.KeyedLDAPFromReaderAt(r, nil)
		})
	if len(ldaps) != 1 || ldaps[0].OpeningPacket != 10 || ldaps[0].Message.BindDN != "cn=reader" ||
		!slices.Equal(ldaps[0].PacketIndices, []int{18}) {
		t.Fatalf("LDAPS was not decoded as in the reference: %+v", ldaps)
	}
	withoutKeys := *capture
	withoutKeys.Secrets = nil
	rows, err := withoutKeys.KeyedLDAP(data, nil)
	if err != nil || len(rows) != 0 {
		t.Fatalf("LDAPS content available without a secret: %v", err)
	}
}
