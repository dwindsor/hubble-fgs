package filters

import (
	"context"
	"fmt"
	"regexp"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	hubbleFilters "github.com/cilium/hubble/pkg/filters"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/filters"
	"github.com/cilium/tetragon/pkg/logger"
)

type URIRegexFilter struct{}

func (f *URIRegexFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc

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

func (f *SNIRegexFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc

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

func (f *DestinationNamesRegexFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc

	if ff.DesintationNamesRegex != nil {
		filter, err := filterByURIRegex(ff.DesintationNamesRegex, f)
		if err != nil {
			return nil, err
		}
		fs = append(fs, filter)
	}

	return fs, nil
}

type DestinationPodRegexFilter struct{}

func (f *DestinationPodRegexFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc

	if ff.DestinationPodRegex != nil {
		filter, err := filterByURIRegex(ff.DestinationPodRegex, f)
		if err != nil {
			return nil, err
		}
		fs = append(fs, filter)
	}

	return fs, nil
}

type DnsNamesRegexFilter struct{}

func (f *DnsNamesRegexFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc

	if ff.DnsNamesRegex != nil {
		filter, err := filterByURIRegex(ff.DnsNamesRegex, f)
		if err != nil {
			return nil, err
		}
		fs = append(fs, filter)
	}

	return fs, nil
}

func filterByURIRegex(uriPatterns []string, f filters.OnBuildFilter) (hubbleFilters.FilterFunc, error) {
	var URIs []*regexp.Regexp

	for _, pattern := range uriPatterns {
		query, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regexp: %v", err)
		}
		URIs = append(URIs, query)
	}

	return func(ev *v1.Event) bool {
		var URIStrings []string

		switch f.(type) {
		case *URIRegexFilter:
			URI, ok := getURI(ev)
			if !ok {
				// Event has no URI field
				return true
			}
			URIStrings = append(URIStrings, URI)
		case *SNIRegexFilter:
			SNI, ok := getSNIName(ev)
			if !ok {
				// Event has no SNI name field
				return true
			}
			URIStrings = append(URIStrings, SNI)
		case *DestinationNamesRegexFilter:
			destinationNames, ok := getDestinationNames(ev)
			if !ok {
				// Event has no DestinationNames name field
				return true
			}
			URIStrings = append(URIStrings, destinationNames...)
		case *DestinationPodRegexFilter:
			pod, ok := getDestinationPod(ev)
			if !ok {
				// Event has no DestinationPod field
				return true
			}
			URIStrings = append(URIStrings, pod)
		case *DnsNamesRegexFilter:
			dnsNames, ok := getDnsNames(ev)
			if !ok {
				// Event has no DestinationNames name field
				return true
			}
			URIStrings = append(URIStrings, dnsNames...)
		default:
			logger.GetLogger().WithField("filter_type", fmt.Sprintf("%T", f)).Error("Unsupported URI / Pod filter type")
			return true
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

type GetURI interface {
	GetURI() string
}

type GetDestinationNames interface {
	GetDestinationNames() []string
}

type GetDestinationPod interface {
	GetDestinationPod() string
}

type GetDnsInfo interface {
	GetDns() *tetragon.DnsInfo
}

func getSNIName(event *v1.Event) (string, bool) {
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

func getURI(event *v1.Event) (string, bool) {
	if event == nil {
		return "", false
	}
	response, ok := event.Event.(*tetragon.GetEventsResponse)
	if !ok {
		return "", false
	}
	ev, ok := tetragon.UnwrapGetEventsResponse(response).(GetURI)
	if !ok {
		return "", false
	}
	return ev.GetURI(), true
}

func getDestinationNames(event *v1.Event) ([]string, bool) {
	if event == nil {
		return nil, false
	}
	response, ok := event.Event.(*tetragon.GetEventsResponse)
	if !ok {
		return nil, false
	}
	ev, ok := tetragon.UnwrapGetEventsResponse(response).(GetDestinationNames)
	if !ok {
		return nil, false
	}
	// ProcessHttp provides a DestnationNames field but it's deprecated so don't match it
	// on this filter
	if _, ok := ev.(*tetragon.ProcessHttp); ok {
		return nil, false
	}
	return ev.GetDestinationNames(), true
}

func getDestinationPod(event *v1.Event) (string, bool) {
	if event == nil {
		return "", false
	}
	response, ok := event.Event.(*tetragon.GetEventsResponse)
	if !ok {
		return "", false
	}
	ev, ok := tetragon.UnwrapGetEventsResponse(response).(GetDestinationPod)
	if !ok {
		return "", false
	}
	return ev.GetDestinationPod(), true
}

func getDnsNames(event *v1.Event) ([]string, bool) {
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
