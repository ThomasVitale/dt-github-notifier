package notification_test

import (
	"errors"
	"testing"

	"github.com/thomasvitale/dt-github-notifier/internal/notification"
	"github.com/thomasvitale/dt-github-notifier/internal/notification/notificationtest"
)

func TestParse(t *testing.T) {
	t.Parallel()
	n, err := notification.Parse(notificationtest.Payload(t, notificationtest.PolicyViolation))
	if err != nil {
		t.Fatal(err)
	}
	if n.Group != notification.GroupPolicyViolation || n.ID != "010ba7f2-ab4a-73b6-a87d-7b9041d17016" {
		t.Errorf("Parse() = group %q, id %q", n.Group, n.ID)
	}

	s, err := notification.DecodeSubject[notification.PolicyViolationSubject](n)
	if err != nil {
		t.Fatal(err)
	}
	c := s.PolicyViolation.Condition
	if c.Policy.Name != "policyName" || c.Policy.ViolationState != "FAIL" || c.Value != "pkg:maven/foo/bar@1.2.3" {
		t.Errorf("DecodeSubject() condition = %+v", c)
	}
	if s.Project.UUID != "c9c9539a-e381-4b36-ac52-6a7ab83b2c95" {
		t.Errorf("DecodeSubject() project UUID = %q", s.Project.UUID)
	}
}

func TestParseInvalid(t *testing.T) {
	t.Parallel()
	for _, body := range []string{`{"notification":`, `[]`, `{}`, `{"notification":null}`, `{"notification":{"id":"x"}}`} {
		if _, err := notification.Parse([]byte(body)); !errors.Is(err, notification.ErrInvalidPayload) {
			t.Errorf("Parse(%s) error = %v, want ErrInvalidPayload", body, err)
		}
	}
}

func TestDecodeSubjectInvalid(t *testing.T) {
	t.Parallel()
	for _, subject := range []string{``, `null`, `[]`, `{"project":"x"}`} {
		n := notification.Notification{Group: notification.GroupNewVulnerability, Subject: []byte(subject)}
		if _, err := notification.DecodeSubject[notification.NewVulnerabilitySubject](n); !errors.Is(err, notification.ErrInvalidPayload) {
			t.Errorf("DecodeSubject(%s) error = %v, want ErrInvalidPayload", subject, err)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add(notificationtest.Payload(f, notificationtest.NewVulnerability))
	f.Add([]byte(`{"notification":{"group":"GROUP_POLICY_VIOLATION","subject":{"project":{"uuid":"x"}}}}`))
	f.Add([]byte(`{"notification":null}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		n, err := notification.Parse(body)
		if err != nil {
			return
		}
		// Decoding any subject must not panic.
		_, _ = notification.DecodeSubject[notification.PolicyViolationSubject](n)
		_, _ = notification.DecodeSubject[notification.NewVulnerabilitySubject](n)
	})
}
