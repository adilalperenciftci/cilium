// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"

	mutation_rules_v3 "github.com/envoyproxy/go-control-plane/envoy/config/common/mutation_rules/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	httpCorsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/cors/v3"
	extauthzv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	grpcStatsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/grpc_stats/v3"
	grpcWebv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/grpc_web/v3"
	luav3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	httpRouterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	statefulsessionv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/stateful_session/v3"
	httpConnectionManagerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_type_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

const (
	// ExtAuthzFilterNamePrefix is the prefix for ext_authz filter instance names.
	// Full name: "<prefix>/<clusterName>". Used as the TypedPerFilterConfig key on routes.
	ExtAuthzFilterNamePrefix = "envoy.filters.http.ext_authz"

	// ExtProcFilterNamePrefix is the prefix for ext_proc (EPP) filter instance names
	// Full name: "<prefix>/<eppClusterName>". Used as the TypedPerFilterConfig key on routes.
	ExtProcFilterNamePrefix = "envoy.filters.http.ext_proc"

	extAuthzRouteMetadataFilterName = "io.cilium.external_auth.route_metadata"
	extAuthzDynamicMetadataName     = "io.cilium.external_auth"
	extAuthzMetadataSelectedKey     = "selected_filter"
	extAuthzMetadataFallbackKey     = "generation_fallback"
	extAuthzMetadataExtProcStateKey = "retained_ext_proc_filters"
	extAuthzLegacyFilterID          = "!legacy"
	extAuthzDisabledFilterID        = "!disabled"
)

const extAuthzRouteMetadataScriptSuffix = `}

function envoy_on_request(request_handle)
  local selected_filter = "!legacy"
  local route_metadata = request_handle:metadata()
  if route_metadata ~= nil then
    local configured = route_metadata:get("selected_filter")
    if configured == "!disabled" or available_filters[configured] then
      selected_filter = configured
    elseif configured ~= nil then
      request_handle:respond({[":status"] = "503"}, "")
      return
    end
  end
  request_handle:streamInfo():dynamicMetadata():set("io.cilium.external_auth", "selected_filter", selected_filter)
  request_handle:clearRouteCache()
end`

// ExtAuthzFilterName returns the HCM filter instance name for a given ext_authz cluster.
func ExtAuthzFilterName(clusterName string) string {
	return fmt.Sprintf("%s/%s", ExtAuthzFilterNamePrefix, clusterName)
}

// ExtProcFilterName returns the HCM filter instance name for a given EPP cluster
func ExtProcFilterName(clusterName string) string {
	return fmt.Sprintf("%s/%s", ExtProcFilterNamePrefix, clusterName)
}

// extAuthzFilterKey returns the established key used for the HCM filter name and
// its per-route override. Keep this serialization stable across LDS/RDS generations.
func extAuthzFilterKey(af *model.HTTPExternalAuthFilter) string {
	clusterName := getClusterName(af.Backend.Namespace, af.Backend.Name, af.Backend.Port.GetPort())
	parts := []string{string(af.Protocol), clusterName}

	if af.PathPrefix != "" {
		parts = append(parts, "pp:"+af.PathPrefix)
	}
	if af.ForwardBody != nil && af.ForwardBody.MaxSize > 0 {
		parts = append(parts, "fb:"+strconv.FormatUint(uint64(af.ForwardBody.MaxSize), 10))
	}
	if len(af.AllowedRequestHeaders) > 0 {
		sorted := append([]string(nil), af.AllowedRequestHeaders...)
		sort.Strings(sorted)
		parts = append(parts, "arh:"+strings.Join(sorted, ","))
	}
	if len(af.AllowedResponseHeaders) > 0 {
		sorted := append([]string(nil), af.AllowedResponseHeaders...)
		sort.Strings(sorted)
		parts = append(parts, "esh:"+strings.Join(sorted, ","))
	}

	return strings.Join(parts, ":")
}

// extAuthzFilterID returns an injective, URL-safe route selector without changing
// the established HCM filter name.
func extAuthzFilterID(af *model.HTTPExternalAuthFilter) string {
	clusterName := getClusterName(af.Backend.Namespace, af.Backend.Name, af.Backend.Port.GetPort())
	var key strings.Builder
	appendExtAuthzFilterIDValue(&key, string(af.Protocol))
	appendExtAuthzFilterIDValue(&key, clusterName)
	appendExtAuthzFilterIDValue(&key, af.PathPrefix)

	maxRequestBytes := "0"
	if af.ForwardBody != nil {
		maxRequestBytes = strconv.FormatUint(uint64(af.ForwardBody.MaxSize), 10)
	}
	appendExtAuthzFilterIDValue(&key, maxRequestBytes)

	requestHeaders := append([]string(nil), af.AllowedRequestHeaders...)
	sort.Strings(requestHeaders)
	appendExtAuthzFilterIDValue(&key, strconv.Itoa(len(requestHeaders)))
	for _, header := range requestHeaders {
		appendExtAuthzFilterIDValue(&key, header)
	}

	responseHeaders := append([]string(nil), af.AllowedResponseHeaders...)
	sort.Strings(responseHeaders)
	appendExtAuthzFilterIDValue(&key, strconv.Itoa(len(responseHeaders)))
	for _, header := range responseHeaders {
		appendExtAuthzFilterIDValue(&key, header)
	}

	return base64.RawURLEncoding.EncodeToString([]byte(key.String()))
}

func appendExtAuthzFilterIDValue(key *strings.Builder, value string) {
	key.WriteString(strconv.Itoa(len(value)))
	key.WriteByte(':')
	key.WriteString(value)
}

func extAuthzFilterNames(authFilters []*model.HTTPExternalAuthFilter) map[string]string {
	keyCounts := make(map[string]int, len(authFilters))
	for _, authFilter := range authFilters {
		keyCounts[extAuthzFilterKey(authFilter)]++
	}

	names := make(map[string]string, len(authFilters))
	for _, authFilter := range authFilters {
		id := extAuthzFilterID(authFilter)
		key := extAuthzFilterKey(authFilter)
		name := ExtAuthzFilterName(key)
		if keyCounts[key] > 1 {
			name += "/" + id
		}
		names[id] = name
	}
	return names
}

type HttpConnectionManagerMutator func(*httpConnectionManagerv3.HttpConnectionManager) *httpConnectionManagerv3.HttpConnectionManager

func WithInternalAddressConfig(enableIpv4, enableIpv6 bool) HttpConnectionManagerMutator {
	return func(hcm *httpConnectionManagerv3.HttpConnectionManager) *httpConnectionManagerv3.HttpConnectionManager {
		hcm.InternalAddressConfig = &httpConnectionManagerv3.HttpConnectionManager_InternalAddressConfig{
			UnixSockets: false,
			CidrRanges:  envoy.GetInternalListenerCIDRs(enableIpv4, enableIpv6),
		}
		return hcm
	}
}

// httpConnectionManagerMutators returns a list of mutator functions for customizing the HTTP connection manager.
func (i *cecTranslator) httpConnectionManagerMutators() []HttpConnectionManagerMutator {
	return []HttpConnectionManagerMutator{
		WithInternalAddressConfig(i.Config.IPConfig.IPv4Enabled, i.Config.IPConfig.IPv6Enabled),
	}
}

func (i *cecTranslator) getHTTPConnectionManagerHttpFilters(m *model.Model) []*httpConnectionManagerv3.HttpFilter {
	hf := []*httpConnectionManagerv3.HttpFilter{}
	if m.GRPCWebTranslationEnabled() {
		hf = append(hf, &httpConnectionManagerv3.HttpFilter{
			Name: "envoy.filters.http.grpc_web",
			ConfigType: &httpConnectionManagerv3.HttpFilter_TypedConfig{
				TypedConfig: toAny(&grpcWebv3.GrpcWeb{}),
			},
		})
	}

	hf = append(hf, &httpConnectionManagerv3.HttpFilter{
		Name: "envoy.filters.http.grpc_stats",
		ConfigType: &httpConnectionManagerv3.HttpFilter_TypedConfig{
			TypedConfig: toAny(&grpcStatsv3.FilterConfig{
				EmitFilterState:     true,
				EnableUpstreamStats: true,
			}),
		},
	})

	authFilters := i.getUniqueAuthFilters(m)
	if len(authFilters) > 0 {
		hf = append(hf, buildExtAuthzRouteMetadataFilter(authFilters))
		filterNames := extAuthzFilterNames(authFilters)
		for _, af := range authFilters {
			hf = append(hf, buildExtAuthzHTTPFilterWithName(af, filterNames[extAuthzFilterID(af)]))
		}
	}

	if epps := getUniqueEPPs(m); len(epps) > 0 {
		for _, epp := range epps {
			hf = append(hf, buildExtProcHTTPFilter(epp))
		}
	}

	// HTTP filter order matters. When CORS is enabled,
	// the CORS filter must run before envoy.filters.http.router.
	if m.IsCORSFilterConfigured() {
		hf = append(hf, &httpConnectionManagerv3.HttpFilter{
			Name: "envoy.filters.http.cors",
			ConfigType: &httpConnectionManagerv3.HttpFilter_TypedConfig{
				TypedConfig: toAny(&httpCorsv3.Cors{}),
			},
		})
	}

	if m.IsSessionPersistenceConfigured() {
		hf = append(hf, &httpConnectionManagerv3.HttpFilter{
			Name: "envoy.filters.http.stateful_session",
			ConfigType: &httpConnectionManagerv3.HttpFilter_TypedConfig{
				TypedConfig: toAny(&statefulsessionv3.StatefulSession{}),
			},
		})
	}

	hf = append(hf, &httpConnectionManagerv3.HttpFilter{
		Name: "envoy.filters.http.router",
		ConfigType: &httpConnectionManagerv3.HttpFilter_TypedConfig{
			TypedConfig: toAny(&httpRouterv3.Router{}),
		},
	})

	return hf
}

func buildExtAuthzRouteMetadataFilter(authFilters []*model.HTTPExternalAuthFilter) *httpConnectionManagerv3.HttpFilter {
	// Older route resources do not carry the marker. The script deliberately defaults
	// to the legacy selection so a newly delivered listener remains compatible until the
	// matching RDS update arrives. If a newer RDS selects a filter absent from this older
	// listener, the script returns a local 503 instead of evaluating a different retained filter.
	var script strings.Builder
	script.WriteString("local available_filters = {\n")
	for _, authFilter := range authFilters {
		fmt.Fprintf(&script, "  [\"%s\"] = true,\n", extAuthzFilterID(authFilter))
	}
	script.WriteString(extAuthzRouteMetadataScriptSuffix)

	return &httpConnectionManagerv3.HttpFilter{
		Name: extAuthzRouteMetadataFilterName,
		ConfigType: &httpConnectionManagerv3.HttpFilter_TypedConfig{
			TypedConfig: toAny(&luav3.Lua{
				DefaultSourceCode: &envoy_config_core.DataSource{
					Specifier: &envoy_config_core.DataSource_InlineString{
						InlineString: script.String(),
					},
				},
			}),
		},
	}
}

// desiredHTTPConnectionManager returns a new HTTP connection manager filter with the given name and route.
func (i *cecTranslator) desiredHTTPConnectionManager(name, routeName string, m *model.Model) (ciliumv2.XDSResource, error) {
	connectionManager := &httpConnectionManagerv3.HttpConnectionManager{
		StatPrefix: name,
		AccessLog:  getHTTPAccessLogs(m),
		RouteSpecifier: &httpConnectionManagerv3.HttpConnectionManager_Rds{
			Rds: &httpConnectionManagerv3.Rds{RouteConfigName: routeName},
		},
		UseRemoteAddress: &wrapperspb.BoolValue{Value: true},
		SkipXffAppend:    false,
		HttpFilters:      i.getHTTPConnectionManagerHttpFilters(m),
		UpgradeConfigs: []*httpConnectionManagerv3.HttpConnectionManager_UpgradeConfig{
			{UpgradeType: "websocket"},
		},
		CommonHttpProtocolOptions: &envoy_config_core.HttpProtocolOptions{
			MaxStreamDuration: &durationpb.Duration{
				Seconds: 0,
			},
		},
	}

	// Apply mutation functions for customizing the connection manager.
	for _, fn := range i.httpConnectionManagerMutators() {
		connectionManager = fn(connectionManager)
	}

	return toXdsResource(connectionManager, envoy.HttpConnectionManagerTypeURL)
}

// buildExtAuthzHTTPFilter creates one named ext_authz HCM HttpFilter for a deduplicated
// external auth config. These filters are positioned before the terminal router filter so
// that per-route TypedPerFilterConfig can enable or disable each instance.
func buildExtAuthzHTTPFilter(af *model.HTTPExternalAuthFilter) *httpConnectionManagerv3.HttpFilter {
	return buildExtAuthzHTTPFilterWithName(af, ExtAuthzFilterName(extAuthzFilterKey(af)))
}

func buildExtAuthzHTTPFilterWithName(af *model.HTTPExternalAuthFilter, filterName string) *httpConnectionManagerv3.HttpFilter {
	var clusterName string
	if af.Protocol == model.ExternalAuthProtocolGRPC {
		clusterName = getGRPCExtAuthClusterName(af.Backend.Namespace, af.Backend.Name, af.Backend.Port.GetPort())
	} else {
		clusterName = getHTTPExtAuthClusterName(af.Backend.Namespace, af.Backend.Name, af.Backend.Port.GetPort())
	}
	var config *extauthzv3.ExtAuthz
	if af.Protocol == model.ExternalAuthProtocolGRPC {
		config = &extauthzv3.ExtAuthz{
			Services: &extauthzv3.ExtAuthz_GrpcService{
				GrpcService: &envoy_config_core.GrpcService{
					TargetSpecifier: &envoy_config_core.GrpcService_EnvoyGrpc_{
						EnvoyGrpc: &envoy_config_core.GrpcService_EnvoyGrpc{
							ClusterName: clusterName,
							// Authority overrides the :authority pseudo-header sent to the
							// auth server. Without this, Envoy uses the cluster name, which
							// after CEC namespace-qualification contains slashes
							// ("ns/cec/cluster") that are illegal in an HTTP/2 authority
							// and cause strict gRPC clients to reset
							// the connection before the handler runs.
							Authority: fmt.Sprintf("%s:%s", af.Backend.Name, af.Backend.Port.GetPort()),
						},
					},
				},
			},
			DecoderHeaderMutationRules: &mutation_rules_v3.HeaderMutationRules{
				DisallowExpression: &envoy_type_matcher_v3.RegexMatcher{
					Regex: "^(:authority|host|content-length)$",
				},
			},
		}
		// Per spec: empty/nil means forward all headers. Leave AllowedHeaders unset
		// so Envoy uses its default (forward all). Only restrict when entries are given.
		if len(af.AllowedRequestHeaders) > 0 {
			config.AllowedHeaders = toListStringMatcher(af.AllowedRequestHeaders)
		}
	} else {
		scheme := "http"
		if af.Backend.TLS != nil {
			scheme = "https"
		}
		httpSvc := &extauthzv3.HttpService{
			ServerUri: &envoy_config_core.HttpUri{
				Uri: fmt.Sprintf("%s://%s:%s", scheme, af.Backend.Name, af.Backend.Port.GetPort()),
				HttpUpstreamType: &envoy_config_core.HttpUri_Cluster{
					Cluster: clusterName,
				},
				Timeout: &durationpb.Duration{Seconds: 10},
			},
			PathPrefix: af.PathPrefix,
		}
		httpSvc.AuthorizationResponse = &extauthzv3.AuthorizationResponse{}
		if len(af.AllowedResponseHeaders) > 0 {
			// Explicit list: forward only those headers (replace semantics).
			httpSvc.AuthorizationResponse.AllowedUpstreamHeaders = toListStringMatcher(af.AllowedResponseHeaders)
		} else {
			// Empty list means forward all per Gateway API spec. Use AllowedUpstreamHeaders
			// (replace, not append) so that a header the auth service returns which already
			// exists on the client request ends up with exactly one value rather than a
			// duplicate that would corrupt the request. Headers describing the message body
			// are excluded by DecoderHeaderMutationRules below.
			httpSvc.AuthorizationResponse.AllowedUpstreamHeaders = allHeadersMatcher()
		}
		config = &extauthzv3.ExtAuthz{
			Services: &extauthzv3.ExtAuthz_HttpService{
				HttpService: httpSvc,
			},
			// Prevent the auth service from overriding routing-critical or
			// message-framing headers regardless of what AllowedUpstreamHeaders
			// matches.
			DecoderHeaderMutationRules: &mutation_rules_v3.HeaderMutationRules{
				DisallowExpression: &envoy_type_matcher_v3.RegexMatcher{
					Regex: "^(:authority|host|content-length)$",
				},
			},
		}
		if len(af.AllowedRequestHeaders) > 0 {
			config.AllowedHeaders = toListStringMatcher(af.AllowedRequestHeaders)
		}
	}

	if af.ForwardBody != nil && af.ForwardBody.MaxSize > 0 {
		config.WithRequestBody = &extauthzv3.BufferSettings{
			MaxRequestBytes:     af.ForwardBody.MaxSize,
			AllowPartialMessage: true,
		}
	}

	config.FilterEnabledMetadata = &envoy_type_matcher_v3.MetadataMatcher{
		Filter: extAuthzDynamicMetadataName,
		Path: []*envoy_type_matcher_v3.MetadataMatcher_PathSegment{
			{
				Segment: &envoy_type_matcher_v3.MetadataMatcher_PathSegment_Key{
					Key: extAuthzMetadataSelectedKey,
				},
			},
		},
		Value: &envoy_type_matcher_v3.ValueMatcher{
			MatchPattern: &envoy_type_matcher_v3.ValueMatcher_OrMatch{
				OrMatch: &envoy_type_matcher_v3.OrMatcher{
					ValueMatchers: []*envoy_type_matcher_v3.ValueMatcher{
						{
							MatchPattern: &envoy_type_matcher_v3.ValueMatcher_StringMatch{
								StringMatch: &envoy_type_matcher_v3.StringMatcher{
									MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{Exact: extAuthzLegacyFilterID},
								},
							},
						},
						{
							MatchPattern: &envoy_type_matcher_v3.ValueMatcher_StringMatch{
								StringMatch: &envoy_type_matcher_v3.StringMatcher{
									MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{Exact: extAuthzFilterID(af)},
								},
							},
						},
					},
				},
			},
		},
	}

	return &httpConnectionManagerv3.HttpFilter{
		Name: filterName,
		ConfigType: &httpConnectionManagerv3.HttpFilter_TypedConfig{
			TypedConfig: toAny(config),
		},
	}
}

// buildExtProcHTTPFilter creates one named ext_proc HCM HTTPFilter for an InferencePool's
// EPP. Similar to ext_authz, these filters are placed before the terminal router filter so
// that the per-route TypedPerFilterConfgi can enable or disable each instance.
func buildExtProcHTTPFilter(epp *model.EndpointPicker) *httpConnectionManagerv3.HttpFilter {
	port := strconv.Itoa(int(epp.Port))
	clusterName := getEPPClusterName(epp)

	config := &extprocv3.ExternalProcessor{
		GrpcService: &envoy_config_core.GrpcService{
			TargetSpecifier: &envoy_config_core.GrpcService_EnvoyGrpc_{
				EnvoyGrpc: &envoy_config_core.GrpcService_EnvoyGrpc{
					ClusterName: clusterName,
					// same workaround as the grpc ext_authz
					Authority: fmt.Sprintf("%s:%s", epp.Name, port),
				},
			},
		},
		ProcessingMode: &extprocv3.ProcessingMode{
			RequestHeaderMode:  extprocv3.ProcessingMode_SEND,
			ResponseHeaderMode: extprocv3.ProcessingMode_SKIP,
			RequestBodyMode:    extprocv3.ProcessingMode_FULL_DUPLEX_STREAMED,
			RequestTrailerMode: extprocv3.ProcessingMode_SEND,
		},
		// FailOpen allows the request through if the EPP is unreachable
		// FailClose drops the request
		FailureModeAllow: epp.FailureMode == "FailOpen",
		MessageTimeout:   &durationpb.Duration{Seconds: 5},
	}
	return &httpConnectionManagerv3.HttpFilter{
		Name:     ExtProcFilterName(clusterName),
		Disabled: true,
		ConfigType: &httpConnectionManagerv3.HttpFilter_TypedConfig{
			TypedConfig: toAny(config),
		},
	}
}

// allHeadersMatcher returns a ListStringMatcher that matches every header name.
func allHeadersMatcher() *envoy_type_matcher_v3.ListStringMatcher {
	return &envoy_type_matcher_v3.ListStringMatcher{
		Patterns: []*envoy_type_matcher_v3.StringMatcher{
			{
				MatchPattern: &envoy_type_matcher_v3.StringMatcher_SafeRegex{
					SafeRegex: &envoy_type_matcher_v3.RegexMatcher{Regex: ".*"},
				},
			},
		},
	}
}

// toListStringMatcher converts a list of exact header names into an Envoy ListStringMatcher.
func toListStringMatcher(headers []string) *envoy_type_matcher_v3.ListStringMatcher {
	if headers == nil {
		return nil
	}
	sortedHeaders := append([]string(nil), headers...)
	sort.Strings(sortedHeaders)
	patterns := make([]*envoy_type_matcher_v3.StringMatcher, 0, len(sortedHeaders))
	for _, h := range sortedHeaders {
		patterns = append(patterns, &envoy_type_matcher_v3.StringMatcher{
			MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
				Exact: h,
			},
			IgnoreCase: true,
		})
	}
	return &envoy_type_matcher_v3.ListStringMatcher{Patterns: patterns}
}
