package v2raya

import "strings"

// CandidatePriority returns the effective auto-selection priority for a node.
// Lower values are preferred. Keeping transport eligibility in one package
// prevents watchdog, dashboard collector and control API from disagreeing
// about how many nodes are actually selectable.
func CandidatePriority(protocol, network, security string, sort int) (int, bool) {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	network = strings.ToLower(strings.TrimSpace(network))
	security = strings.ToLower(strings.TrimSpace(security))

	base, ok := CandidatePriorityBase(protocol, network, security)
	if !ok {
		return 0, false
	}
	return base + sort, true
}

// CandidatePriorityBase returns the transport-class base priority.
func CandidatePriorityBase(protocol, network, security string) (int, bool) {
	switch {
	case protocol == "hysteria2":
		return 20, true
	case protocol == "vless" && network == "xhttp" && security == "reality":
		return 40, true
	case protocol == "shadowsocks":
		return 60, true
	case protocol == "vless" && network == "ws" && security == "tls":
		return 80, true
	case protocol == "vless" && network == "tcp" && security == "reality":
		return 100, true
	default:
		return 0, false
	}
}

// CandidateEligible reports whether the node participates in automatic
// selection, without exposing scoring details to callers that only need a
// count.
func CandidateEligible(protocol, network, security string) bool {
	_, ok := CandidatePriorityBase(
		strings.ToLower(strings.TrimSpace(protocol)),
		strings.ToLower(strings.TrimSpace(network)),
		strings.ToLower(strings.TrimSpace(security)),
	)
	return ok
}
