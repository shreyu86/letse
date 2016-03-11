package route53

// Credentials are automatically looked up by the SDK, checking for the following
// environment variables:
//
// * AWS_ACCESS_KEY_ID
// * AWS_SECRET_ACCESS_KEY
// * AWS_REGION
//

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/route53"
)

// Route53 implements AWS Route53 DNS provider.
type Route53 struct {
	svc            *route53.Route53
	domain, zoneID string
	rrs            *route53.ResourceRecordSet
}

// New initializes and returns a new instance of the Route53 provider.
func New(domain string) *Route53 {
	zone, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		log.Fatalf("unable to get zone name from domain %q", domain)
	}

	// Since Route53 returns it with dot at the end when listing zones.
	zone += "."

	svc := route53.New(session.New())
	params := &route53.ListHostedZonesByNameInput{
		DNSName: aws.String(zone),
	}

	resp, err := svc.ListHostedZonesByName(params)
	if err != nil {
		log.Fatal(err)
	}

	// Does binary search on lexicographically ordered hosted zones slice, in
	// order to find the correspondent Route53 zone ID for the given zone name.
	l := len(resp.HostedZones)
	i := sort.Search(l, func(i int) bool {
		return *resp.HostedZones[i].Name == zone
	})

	var zoneID string
	if i < l && *resp.HostedZones[i].Name == zone {
		zoneID = strings.Split(*resp.HostedZones[i].Id, "/")[2]
	} else {
		log.Fatalf("unable to find hosted zone %q in Route53", zone)
	}

	return &Route53{
		svc:    svc,
		zoneID: zoneID,
		domain: domain,
	}
}

// AddTXTRecord create a resource record in Route53, with the given name and value.
// It waits until the resource record is fully synced to all Route53 servers.
func (r *Route53) AddTXTRecord(name, value string) error {
	r.rrs = &route53.ResourceRecordSet{
		Name: aws.String(name + "." + r.domain),
		Type: aws.String("TXT"),
		TTL:  aws.Int64(30),
		ResourceRecords: []*route53.ResourceRecord{
			{
				Value: aws.String(fmt.Sprintf(`%q`, value)),
			},
		},
	}

	changeBatch := &route53.ChangeBatch{
		Comment: aws.String("Managed by Letse"),
		Changes: []*route53.Change{
			&route53.Change{
				Action:            aws.String("UPSERT"),
				ResourceRecordSet: r.rrs,
			},
		},
	}

	req := &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(r.zoneID),
		ChangeBatch:  changeBatch,
	}

	log.Printf("[DEBUG] Creating resource records for zone: %s, name: %s\n\n%s",
		r.zoneID, *r.rrs.Name, req)

	resp, err := r.svc.ChangeResourceRecordSets(req)
	if err != nil {
		return err
	}

	changeRequest := &route53.GetChangeInput{
		Id: aws.String(*resp.ChangeInfo.Id),
	}

	ticker := time.NewTicker(time.Second * 1).C
	timeout := time.NewTimer(time.Second * 120).C

	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for Route53 changes to fully sync")
		case <-ticker:
			status, err := r.svc.GetChange(changeRequest)
			if err != nil {
				log.Printf("error getting change update from Route53 service: %s\n", err)
			}

			log.Printf("route53 change status: %s", *status.ChangeInfo.Status)
			if *status.ChangeInfo.Status == "INSYNC" {
				return nil
			}
		}
	}
}

// RemoveTXTRecord removes a TXT resource record from Route53, given its name. It
// does not wait for Route53 servers to fully sync the change.
func (r *Route53) RemoveTXTRecord(name string) error {
	changeBatch := &route53.ChangeBatch{
		Comment: aws.String("Managed by Letse"),
		Changes: []*route53.Change{
			&route53.Change{
				Action:            aws.String("DELETE"),
				ResourceRecordSet: r.rrs,
			},
		},
	}

	req := &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(r.zoneID),
		ChangeBatch:  changeBatch,
	}

	log.Printf("[DEBUG] Deleting TXT record from zone: %s, name: %s\n\n%s",
		r.zoneID, *r.rrs.Name, req)

	_, err := r.svc.ChangeResourceRecordSets(req)
	return err
}
