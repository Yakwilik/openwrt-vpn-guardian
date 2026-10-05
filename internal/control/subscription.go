package control

import (
	"fmt"
	"strings"
)

// SubscriptionInfo is the dashboard representation of a v2rayA subscription.
// Address is populated only for management responses and omitted otherwise.
type SubscriptionInfo struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Address    string `json:"address,omitempty"`
	Host       string `json:"host"`
	Info       string `json:"info"`
	Remarks    string `json:"remarks"`
	AutoSelect bool   `json:"autoSelect"`
	NodeCount  int    `json:"nodeCount"`
}

func subscriptionInfoFromMap(sm map[string]any, includeSecrets bool) SubscriptionInfo {
	sub := SubscriptionInfo{
		ID:         intValue(sm["id"]),
		Host:       stringValue(sm["host"]),
		Info:       stringValue(sm["info"]),
		Remarks:    stringValue(sm["remarks"]),
		AutoSelect: boolValue(sm["autoSelect"]),
	}

	if includeSecrets {
		sub.Address = stringValue(sm["address"])
	}
	if servers, ok := sm["servers"].([]any); ok {
		sub.NodeCount = len(servers)
	}

	switch {
	case sub.Remarks != "":
		sub.Name = sub.Remarks
	case sub.Host != "":
		sub.Name = sub.Host
	default:
		sub.Name = fmt.Sprintf("Subscription #%d", sub.ID)
	}
	return sub
}

// stringValue normalizes optional JSON text without stringifying nulls,
// numbers or compound values from an unexpected upstream response.
func stringValue(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}
