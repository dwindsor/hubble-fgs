package http

import "strconv"

var (
	HttpMultiMessage = uint32(0x1)
)

var httpMethod = map[uint32]string{
	0:  "internal-error",
	1:  "CONNECT",
	2:  "DELETE",
	3:  "GET",
	4:  "HEAD",
	5:  "OPTIONS",
	6:  "POST",
	7:  "PULL",
	8:  "PATCH",
	9:  "TRACE",
	10: "unknown",
	11: "response",
}

func GetHttpMethod(code uint32) string {
	methodName := httpMethod[code]
	if methodName == "" {
		return "unknown-method"
	}
	return methodName
}

func GetHttpCode(code string) (uint32, error) {
	i, err := strconv.ParseUint(code, 10, 0)
	if err != nil {
		return uint32(0), err
	}
	return uint32(i), err
}
