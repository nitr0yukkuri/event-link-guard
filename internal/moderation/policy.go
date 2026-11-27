package moderation

import (
	"event-link-guard/internal/guard"
	"event-link-guard/internal/spam"
)

type Decision struct {
	Delete bool
	Notify bool
}

type Policy struct {
	EnforceURL bool
	EnforceSpam bool
}

func (p Policy) URL(r guard.Result) Decision {
	switch r.Verdict {
	case guard.Threat:
		return Decision{Delete: p.EnforceURL, Notify: true}
	case guard.Unknown:
		return Decision{Notify: true}
	default:
		return Decision{}
	}
}

func (p Policy) Spam(r spam.Result) Decision {
	if r.Reason == "" || r.Duplicate || r.CapacityExceeded {
		return Decision{}
	}
	return Decision{Delete: p.EnforceSpam, Notify: r.Alert}
}
