package policy

import (
	"encoding/json"
)

func ConvertPolicyMsgToJson(policyMsg *FwPolicyMsgV2) string {
	jsonData, err := json.Marshal(policyMsg)
	if err != nil {
		return ""
	}
	return string(jsonData)
}
