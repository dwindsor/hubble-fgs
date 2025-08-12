package filters

import (
	"context"
	"fmt"
	"regexp"

	"github.com/cilium/tetragon/pkg/event"
	"github.com/cilium/tetragon/pkg/filters"
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

type URIRegexFilter struct{}

func (f *URIRegexFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]filters.FilterFunc, error) {
	var fs []filters.FilterFunc

	if ff.UriRegex != nil {
		filter, err := filterByURIRegex(ff.UriRegex, f)
		if err != nil {
			return nil, err
		}
		fs = append(fs, filter)
	}

	return fs, nil
}

type SNIRegexFilter struct{}

func (f *SNIRegexFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]filters.FilterFunc, error) {
	var fs []filters.FilterFunc

	if ff.SniRegex != nil {
		filter, err := filterByURIRegex(ff.SniRegex, f)
		if err != nil {
			return nil, err
		}
		fs = append(fs, filter)
	}

	return fs, nil
}

type DestinationNamesRegexFilter struct{}

func (f *DestinationNamesRegexFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]filters.FilterFunc, error) {
	var fs []filters.FilterFunc

	if ff.DestinationNamesRegex != nil {
		filter, err := filterByURIRegex(ff.DestinationNamesRegex, f)
		if err != nil {
			return nil, err
		}
		fs = append(fs, filter)
	}

	return fs, nil
}

type DestinationPodRegexFilter struct{}

func (f *DestinationPodRegexFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]filters.FilterFunc, error) {
	var fs []filters.FilterFunc

	if ff.DestinationPodRegex != nil {
		filter, err := filterByURIRegex(ff.DestinationPodRegex, f)
		if err != nil {
			return nil, err
		}
		fs = append(fs, filter)
	}

	return fs, nil
}

type DestinationNamespaceRegexFilter struct{}

func (f *DestinationNamespaceRegexFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]filters.FilterFunc, error) {
	var fs []filters.FilterFunc

	if ff.DestinationNamespaceRegex != nil {
		filter, err := filterByURIRegex(ff.DestinationNamespaceRegex, f)
		if err != nil {
			return nil, err
		}
		fs = append(fs, filter)
	}

	return fs, nil
}

type DnsNamesRegexFilter struct{}

func (f *DnsNamesRegexFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]filters.FilterFunc, error) {
	var fs []filters.FilterFunc

	if ff.DnsNamesRegex != nil {
		filter, err := filterByURIRegex(ff.DnsNamesRegex, f)
		if err != nil {
			return nil, err
		}
		fs = append(fs, filter)
	}

	return fs, nil
}

type HostRegexFilter struct{}

func (f *HostRegexFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]filters.FilterFunc, error) {
	var fs []filters.FilterFunc

	if ff.HostRegex != nil {
		filter, err := filterByURIRegex(ff.HostRegex, f)
		if err != nil {
			return nil, err
		}
		fs = append(fs, filter)
	}

	return fs, nil
}

func filterByURIRegex(uriPatterns []string, f filters.OnBuildFilter) (filters.FilterFunc, error) {
	var URIs []*regexp.Regexp

	for _, pattern := range uriPatterns {
		query, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regexp: %v", err)
		}
		URIs = append(URIs, query)
	}

	return func(ev *event.Event) bool {
		var URIStrings []string

		switch f.(type) {
		case *URIRegexFilter:
			request, ok := getHttpRequest(ev)
			if !ok {
				// Event has no Http.Request field
				return false
			}
			URIStrings = append(URIStrings, request.Uri)
		case *SNIRegexFilter:
			SNI, ok := getSNIName(ev)
			if !ok {
				// Event has no SNI name field
				return false
			}
			URIStrings = append(URIStrings, SNI)
		case *DestinationNamesRegexFilter:
			destinationNames, ok := getDestinationNames(ev)
			if !ok {
				// Event has no DestinationNames name field
				return false
			}
			URIStrings = append(URIStrings, destinationNames...)
		case *DestinationPodRegexFilter:
			pod, ok := getDestinationPod(ev)
			if !ok {
				// Event has no DestinationPod field
				return false
			}
			URIStrings = append(URIStrings, pod)
		case *DnsNamesRegexFilter:
			dnsNames, ok := getDnsNames(ev)
			if !ok {
				// Event has no DestinationNames name field
				return false
			}
			URIStrings = append(URIStrings, dnsNames...)
		case *HostRegexFilter:
			request, ok := getHttpRequest(ev)
			if !ok {
				// Event has no Http.Request field
				return false
			}
			URIStrings = append(URIStrings, request.Host)
		case *DestinationNamespaceRegexFilter:
			ns, ok := getDestinationNamespace(ev)
			if !ok {
				// Event has no DestinationNamespace field
				return false
			}
			URIStrings = append(URIStrings, ns)
		default:
			logger.GetLogger().Error("Unsupported URI / Pod filter type", "filter_type", fmt.Sprintf("%T", f))
			return false
		}

		// Nested for loop to handle the case where we have more than one URI string, e.g.
		// in the case of the DestinationNames field which may container one or more
		// destination names.
		for _, URI := range URIs {
			for _, URIString := range URIStrings {
				if URI.MatchString(URIString) {
					return true
				}
			}
		}

		return false
	}, nil
}

type GetSNIName interface {
	GetSniName() string
}

type GetDestinationNames interface {
	GetDestinationNames() []string
}

type GetDestinationPod interface {
	GetDestinationPod() *tetragon.Pod
}

type GetDnsInfo interface {
	GetDns() *tetragon.DnsInfo
}

type GetSocket interface {
	GetSocket() *tetragon.SockInfo
}

type GetHttp interface {
	GetHttp() *tetragon.HttpInfo
}

func getSNIName(event *event.Event) (string, bool) {
	if event == nil {
		return "", false
	}
	response, ok := event.Event.(*tetragon.GetEventsResponse)
	if !ok {
		return "", false
	}
	ev, ok := tetragon.UnwrapGetEventsResponse(response).(GetSNIName)
	if !ok {
		return "", false
	}
	return ev.GetSniName(), true
}

func getDestinationNames(event *event.Event) ([]string, bool) {
	if event == nil {
		return nil, false
	}
	response, ok := event.Event.(*tetragon.GetEventsResponse)
	if !ok {
		return nil, false
	}

	// If the event has socket info, use that instead
	if _, ok := tetragon.UnwrapGetEventsResponse(response).(GetSocket); ok {
		sockInfo, ok := getSockInfo(event)
		if !ok {
			return nil, false
		}
		return sockInfo.DestinationNames, ok
	}

	ev, ok := tetragon.UnwrapGetEventsResponse(response).(GetDestinationNames)
	if !ok {
		return nil, false
	}
	return ev.GetDestinationNames(), true
}

func getDestinationPod(event *event.Event) (string, bool) {
	if event == nil {
		return "", false
	}
	response, ok := event.Event.(*tetragon.GetEventsResponse)
	if !ok {
		return "", false
	}

	// If the event has socket info, use that instead
	if _, ok := tetragon.UnwrapGetEventsResponse(response).(GetSocket); ok {
		sockInfo, ok := getSockInfo(event)
		if !ok {
			return "", false
		}
		if sockInfo.DestinationPod == nil {
			return "", false
		}
		return sockInfo.DestinationPod.Name, ok
	}

	ev, ok := tetragon.UnwrapGetEventsResponse(response).(GetDestinationPod)
	if !ok {
		return "", false
	}
	pod := ev.GetDestinationPod()
	if pod == nil {
		return "", false
	}
	return pod.Name, true
}

func getDestinationNamespace(event *event.Event) (string, bool) {
	if event == nil {
		return "", false
	}
	response, ok := event.Event.(*tetragon.GetEventsResponse)
	if !ok {
		return "", false
	}

	// If the event has socket info, use that instead
	if _, ok := tetragon.UnwrapGetEventsResponse(response).(GetSocket); ok {
		sockInfo, ok := getSockInfo(event)
		if !ok {
			return "", false
		}
		if sockInfo.DestinationPod == nil {
			return "", false
		}
		return sockInfo.DestinationPod.Namespace, ok
	}

	ev, ok := tetragon.UnwrapGetEventsResponse(response).(GetDestinationPod)
	if !ok {
		return "", false
	}
	pod := ev.GetDestinationPod()
	if pod == nil {
		return "", false
	}
	return pod.Namespace, true
}

func getDnsNames(event *event.Event) ([]string, bool) {
	if event == nil {
		return nil, false
	}
	response, ok := event.Event.(*tetragon.GetEventsResponse)
	if !ok {
		return nil, false
	}
	ev, ok := tetragon.UnwrapGetEventsResponse(response).(GetDnsInfo)
	if !ok {
		return nil, false
	}
	dns := ev.GetDns()
	if dns == nil {
		return nil, false
	}
	return dns.Names, true
}

func getSockInfo(event *event.Event) (*tetragon.SockInfo, bool) {
	if event == nil {
		return nil, false
	}
	response, ok := event.Event.(*tetragon.GetEventsResponse)
	if !ok {
		return nil, false
	}
	ev, ok := tetragon.UnwrapGetEventsResponse(response).(GetSocket)
	if !ok {
		return nil, false
	}
	socket := ev.GetSocket()
	if socket == nil {
		return nil, false
	}
	return socket, true
}

func getHttpRequest(event *event.Event) (*tetragon.HttpRequest, bool) {
	if event == nil {
		return nil, false
	}
	response, ok := event.Event.(*tetragon.GetEventsResponse)
	if !ok {
		return nil, false
	}
	ev, ok := tetragon.UnwrapGetEventsResponse(response).(GetHttp)
	if !ok {
		return nil, false
	}
	http := ev.GetHttp()
	if http == nil {
		return nil, false
	}
	if http.Request == nil {
		return nil, false
	}
	return http.Request, true
}
