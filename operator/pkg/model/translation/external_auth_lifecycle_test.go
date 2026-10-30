// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"testing"

	listenerV3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routeV3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	extauthzV3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	hcmV3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_type_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestRetainExternalAuthFilterTombstones(t *testing.T) {
	filterA := ExtAuthzFilterName("HTTP:default:auth-a:8080")
	filterB := ExtAuthzFilterName("HTTP:default:auth-b:8080")

	// This listener represents a resource produced before route metadata gating
	// existed. The next RDS must still disable A after the desired listener drops it.
	existing := externalAuthLifecycleCEC(t, false, []string{filterA, filterB}, map[string]bool{
		filterA: false,
		filterB: true,
	})
	desired := externalAuthLifecycleCEC(t, true, []string{filterB}, map[string]bool{
		filterB: false,
	})

	require.NoError(t, RetainExternalAuthFilterTombstones(existing, desired))
	requireExternalAuthPerRouteDisabled(t, desired, filterA, true)
	requireExternalAuthPerRouteDisabled(t, desired, filterB, false)
	requireExternalAuthVirtualHostDisabled(t, desired, filterA, true)
	requireExternalAuthVirtualHostDisabled(t, desired, filterB, true)

	// Persist route tombstones after the old listener resource is replaced so a
	// later reconciliation cannot drop them while retained connections still drain.
	withoutAuth := externalAuthLifecycleCEC(t, false, nil, nil)
	require.NoError(t, RetainExternalAuthFilterTombstones(desired, withoutAuth))
	requireExternalAuthPerRouteDisabled(t, withoutAuth, filterA, true)
	requireExternalAuthPerRouteDisabled(t, withoutAuth, filterB, true)
	require.Equal(t, extAuthzDisabledFilterID, externalAuthLifecycleRouteSelection(t, withoutAuth))

	// Reintroducing a filter removes it from the tombstone set and preserves the
	// current route's explicitly enabled configuration.
	reintroduced := externalAuthLifecycleCEC(t, true, []string{filterA}, map[string]bool{
		filterA: false,
	})
	require.NoError(t, RetainExternalAuthFilterTombstones(withoutAuth, reintroduced))
	requireExternalAuthPerRouteDisabled(t, reintroduced, filterA, false)
	requireExternalAuthPerRouteDisabled(t, reintroduced, filterB, true)
}

func TestRetainExternalAuthFilterTombstonesKeepsNewFilterOutsideBaseline(t *testing.T) {
	filterA := ExtAuthzFilterName("HTTP:default:auth-a:8080")
	filterB := ExtAuthzFilterName("HTTP:default:auth-b:8080")
	existing := externalAuthLifecycleCEC(t, false, []string{filterA}, map[string]bool{filterA: false})
	desired := externalAuthLifecycleCEC(t, true, []string{filterB}, map[string]bool{filterB: false})

	require.NoError(t, RetainExternalAuthFilterTombstones(existing, desired))
	requireExternalAuthVirtualHostDisabled(t, desired, filterA, true)
}

func TestUnlockExternalAuthRouteGates(t *testing.T) {
	filterA := ExtAuthzFilterName("HTTP:default:auth-a:8080")
	actual := &routeV3.Route{
		Match: &routeV3.RouteMatch{DynamicMetadata: []*envoy_type_matcher_v3.MetadataMatcher{{
			Filter: extAuthzDynamicMetadataName,
			Path: []*envoy_type_matcher_v3.MetadataMatcher_PathSegment{{
				Segment: &envoy_type_matcher_v3.MetadataMatcher_PathSegment_Key{Key: extAuthzMetadataSelectedKey},
			}},
		}}},
		TypedPerFilterConfig: map[string]*anypb.Any{
			filterA: toAny(&extauthzV3.ExtAuthzPerRoute{
				Override: &extauthzV3.ExtAuthzPerRoute_Disabled{Disabled: false},
			}),
		},
	}
	fallback := proto.Clone(actual).(*routeV3.Route)
	fallback.Match.DynamicMetadata = nil
	fallback.Metadata = externalAuthRouteMetadata("selector")
	fallback.Metadata.FilterMetadata[extAuthzRouteMetadataFilterName].Fields[extAuthzMetadataFallbackKey] = structpb.NewBoolValue(true)
	fallback.Action = &routeV3.Route_DirectResponse{DirectResponse: &routeV3.DirectResponseAction{Status: 503}}

	got, err := unlockExternalAuthRouteGates([]*routeV3.Route{actual, fallback}, map[string]struct{}{filterA: struct{}{}})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Empty(t, got[0].GetMatch().GetDynamicMetadata())

	got, err = unlockExternalAuthRouteGates([]*routeV3.Route{actual, fallback}, map[string]struct{}{})
	require.NoError(t, err)
	require.Len(t, got, 2)
}

func TestRetainExternalAuthFilterTombstonesRemainBoundedAfterPatch(t *testing.T) {
	filterA := ExtAuthzFilterName("HTTP:default:auth-a:8080")
	existing := externalAuthLifecycleCEC(t, true, []string{filterA}, map[string]bool{filterA: false})
	desired := externalAuthLifecycleCEC(t, false, nil, nil)

	require.NoError(t, RetainExternalAuthFilterTombstones(existing, desired))
	requireExternalAuthVirtualHostMissing(t, desired, filterA)
	require.Equal(t, extAuthzDisabledFilterID, externalAuthLifecycleRouteSelection(t, desired))

	next := externalAuthLifecycleCEC(t, false, nil, nil)
	require.NoError(t, RetainExternalAuthFilterTombstones(desired, next))
	requireExternalAuthVirtualHostMissing(t, next, filterA)
	require.Equal(t, extAuthzDisabledFilterID, externalAuthLifecycleRouteSelection(t, next))
}

func TestRetainExternalAuthFallbackDisablesHistoricalExtProc(t *testing.T) {
	authA := &model.HTTPExternalAuthFilter{
		Backend:  model.Backend{Name: "auth-a", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
		Protocol: model.ExternalAuthProtocolHTTP,
	}
	authB := &model.HTTPExternalAuthFilter{
		Backend:  model.Backend{Name: "auth-b", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
		Protocol: model.ExternalAuthProtocolHTTP,
	}
	filterA := ExtAuthzFilterName(extAuthzFilterKey(authA))
	filterB := ExtAuthzFilterName(extAuthzFilterKey(authB))
	oldExtProc := ExtProcFilterName("default:old-epp:9002")
	existing := externalAuthLifecycleCEC(t, false, []string{filterA, oldExtProc}, map[string]bool{filterA: false})
	desired := externalAuthLifecycleCEC(t, true, []string{filterB}, map[string]bool{filterB: false})
	setExternalAuthLifecycleGatedRoute(t, desired, authB)

	require.NoError(t, RetainExternalAuthFilterTombstones(existing, desired))
	virtualHost := externalAuthLifecycleVirtualHost(t, desired)
	require.Len(t, virtualHost.GetRoutes(), 2)
	fallback := virtualHost.GetRoutes()[1]
	requireExternalAuthExtProcDisabled(t, fallback, oldExtProc)

	next := externalAuthLifecycleCEC(t, true, []string{filterB}, map[string]bool{filterB: false})
	setExternalAuthLifecycleGatedRoute(t, next, authB)
	require.NoError(t, RetainExternalAuthFilterTombstones(desired, next))
	entry := externalAuthLifecycleVirtualHost(t, next).GetRoutes()[1].GetTypedPerFilterConfig()[oldExtProc]
	require.NotNil(t, entry, "the bounded pre-selector ext_proc set must persist across later reconciliations")
}

func TestRetainExternalAuthActualRouteDisablesRemovedHistoricalExtProc(t *testing.T) {
	authA := &model.HTTPExternalAuthFilter{
		Backend:  model.Backend{Name: "auth-a", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
		Protocol: model.ExternalAuthProtocolHTTP,
	}
	filterA := ExtAuthzFilterName(extAuthzFilterKey(authA))
	oldExtProc := ExtProcFilterName("default:old-epp:9002")
	existing := externalAuthLifecycleCEC(t, false, []string{filterA, oldExtProc}, map[string]bool{filterA: false})
	desired := externalAuthLifecycleCEC(t, true, []string{filterA}, map[string]bool{filterA: false})
	setExternalAuthLifecycleGatedRoute(t, desired, authA)

	require.NoError(t, RetainExternalAuthFilterTombstones(existing, desired))
	virtualHost := externalAuthLifecycleVirtualHost(t, desired)
	require.Len(t, virtualHost.GetRoutes(), 1, "the retained authorization filter should unlock the actual route")
	requireExternalAuthExtProcDisabled(t, virtualHost.GetRoutes()[0], oldExtProc)

	withoutAuth := externalAuthLifecycleCEC(t, false, nil, nil)
	require.NoError(t, RetainExternalAuthFilterTombstones(desired, withoutAuth))
	virtualHost = externalAuthLifecycleVirtualHost(t, withoutAuth)
	require.Len(t, virtualHost.GetRoutes(), 1)
	requireExternalAuthExtProcDisabled(t, virtualHost.GetRoutes()[0], oldExtProc)
}

func TestRetainExternalAuthActualRouteDisablesRemovedSelectorExtProc(t *testing.T) {
	authA := &model.HTTPExternalAuthFilter{
		Backend:  model.Backend{Name: "auth-a", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
		Protocol: model.ExternalAuthProtocolHTTP,
	}
	filterA := ExtAuthzFilterName(extAuthzFilterKey(authA))
	oldExtProc := ExtProcFilterName("default:old-epp:9002")
	existing := externalAuthLifecycleCEC(t, true, []string{filterA, oldExtProc}, map[string]bool{filterA: false})
	desired := externalAuthLifecycleCEC(t, true, []string{filterA}, map[string]bool{filterA: false})
	setExternalAuthLifecycleGatedRoute(t, desired, authA)

	require.NoError(t, RetainExternalAuthFilterTombstones(existing, desired))
	virtualHost := externalAuthLifecycleVirtualHost(t, desired)
	require.Len(t, virtualHost.GetRoutes(), 2)
	requireExternalAuthExtProcDisabled(t, virtualHost.GetRoutes()[0], oldExtProc)
	requireExternalAuthExtProcDisabled(t, virtualHost.GetRoutes()[1], oldExtProc)

	withoutAuth := externalAuthLifecycleCEC(t, false, nil, nil)
	require.NoError(t, RetainExternalAuthFilterTombstones(desired, withoutAuth))
	requireExternalAuthExtProcDisabled(t, externalAuthLifecycleVirtualHost(t, withoutAuth).GetRoutes()[0], oldExtProc)

	directWithoutAuth := externalAuthLifecycleCEC(t, false, nil, nil)
	require.NoError(t, RetainExternalAuthFilterTombstones(existing, directWithoutAuth))
	requireExternalAuthExtProcDisabled(t, externalAuthLifecycleVirtualHost(t, directWithoutAuth).GetRoutes()[0], oldExtProc)
}

func TestRetainExternalAuthActualRouteKeepsCurrentExtProc(t *testing.T) {
	authA := &model.HTTPExternalAuthFilter{
		Backend:  model.Backend{Name: "auth-a", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
		Protocol: model.ExternalAuthProtocolHTTP,
	}
	filterA := ExtAuthzFilterName(extAuthzFilterKey(authA))
	currentExtProc := ExtProcFilterName("default:current-epp:9002")
	existing := externalAuthLifecycleCEC(t, false, []string{filterA, currentExtProc}, map[string]bool{filterA: false})
	desired := externalAuthLifecycleCEC(t, true, []string{filterA, currentExtProc}, map[string]bool{filterA: false})
	setExternalAuthLifecycleExtProcDefaultDisabled(t, desired, currentExtProc)
	setExternalAuthLifecycleGatedRoute(t, desired, authA)
	setExternalAuthLifecycleExtProcRouteDisabled(t, desired, currentExtProc, false)

	require.NoError(t, RetainExternalAuthFilterTombstones(existing, desired))
	actual := externalAuthLifecycleVirtualHost(t, desired).GetRoutes()[0]
	requireExternalAuthExtProcEnabled(t, actual, currentExtProc)
}

func TestRetainExternalAuthExtProcHistoryRemainsBounded(t *testing.T) {
	authA := &model.HTTPExternalAuthFilter{
		Backend:  model.Backend{Name: "auth-a", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
		Protocol: model.ExternalAuthProtocolHTTP,
	}
	filterA := ExtAuthzFilterName(extAuthzFilterKey(authA))
	legacyExtProc := ExtProcFilterName("default:legacy-epp:9002")
	extProcOne := ExtProcFilterName("default:epp-one:9002")
	extProcTwo := ExtProcFilterName("default:epp-two:9002")

	legacy := externalAuthLifecycleCEC(t, false, []string{filterA, legacyExtProc}, map[string]bool{filterA: false})
	first := externalAuthLifecycleCEC(t, true, []string{filterA, extProcOne}, map[string]bool{filterA: false})
	setExternalAuthLifecycleExtProcDefaultDisabled(t, first, extProcOne)
	setExternalAuthLifecycleGatedRoute(t, first, authA)
	setExternalAuthLifecycleExtProcRouteDisabled(t, first, extProcOne, false)
	require.NoError(t, RetainExternalAuthFilterTombstones(legacy, first))

	second := externalAuthLifecycleCEC(t, true, []string{filterA, extProcTwo}, map[string]bool{filterA: false})
	setExternalAuthLifecycleExtProcDefaultDisabled(t, second, extProcTwo)
	setExternalAuthLifecycleGatedRoute(t, second, authA)
	setExternalAuthLifecycleExtProcRouteDisabled(t, second, extProcTwo, false)
	require.NoError(t, RetainExternalAuthFilterTombstones(first, second))

	actual := externalAuthLifecycleVirtualHost(t, second).GetRoutes()[0]
	requireExternalAuthExtProcDisabled(t, actual, legacyExtProc)
	require.NotContains(t, actual.GetTypedPerFilterConfig(), extProcOne,
		"default-disabled selector generations must not accumulate historical filter names")
	requireExternalAuthExtProcEnabled(t, actual, extProcTwo)
	retained := actual.GetMetadata().GetFilterMetadata()[extAuthzRouteMetadataFilterName].GetFields()[extAuthzMetadataExtProcStateKey].GetStructValue().GetFields()
	require.Equal(t, map[string]*structpb.Value{legacyExtProc: structpb.NewBoolValue(true)}, retained)
}

func setExternalAuthLifecycleGatedRoute(t *testing.T, cec *ciliumv2.CiliumEnvoyConfig, auth *model.HTTPExternalAuthFilter) {
	t.Helper()
	for i := range cec.Spec.Resources {
		resource := &cec.Spec.Resources[i]
		if resource.GetTypeUrl() != envoy.RouteTypeURL {
			continue
		}
		routeConfig := &routeV3.RouteConfiguration{}
		require.NoError(t, proto.Unmarshal(resource.GetValue(), routeConfig))
		base := routeConfig.GetVirtualHosts()[0].GetRoutes()[0]
		base.Match = &routeV3.RouteMatch{PathSpecifier: &routeV3.RouteMatch_Prefix{Prefix: "/"}}
		base.Metadata = getExternalAuthRouteMetadata(auth, []*model.HTTPExternalAuthFilter{auth})
		actual, fallback := externalAuthRouteGate(base, auth, []*model.HTTPExternalAuthFilter{auth}, nil, false)
		routeConfig.GetVirtualHosts()[0].Routes = []*routeV3.Route{actual, fallback}
		value, err := proto.Marshal(routeConfig)
		require.NoError(t, err)
		resource.Value = value
		return
	}
	t.Fatal("route configuration resource not found")
}

func setExternalAuthLifecycleExtProcDefaultDisabled(t *testing.T, cec *ciliumv2.CiliumEnvoyConfig, filterName string) {
	t.Helper()
	for i := range cec.Spec.Resources {
		resource := &cec.Spec.Resources[i]
		if resource.GetTypeUrl() != envoy.ListenerTypeURL {
			continue
		}
		listener := &listenerV3.Listener{}
		require.NoError(t, proto.Unmarshal(resource.GetValue(), listener))
		for _, chain := range listener.GetFilterChains() {
			for _, networkFilter := range chain.GetFilters() {
				hcm := &hcmV3.HttpConnectionManager{}
				require.NoError(t, networkFilter.GetTypedConfig().UnmarshalTo(hcm))
				for _, filter := range hcm.GetHttpFilters() {
					if filter.GetName() == filterName {
						filter.Disabled = true
					}
				}
				networkFilter.ConfigType = &listenerV3.Filter_TypedConfig{TypedConfig: toAny(hcm)}
			}
		}
		value, err := proto.Marshal(listener)
		require.NoError(t, err)
		resource.Value = value
		return
	}
	t.Fatal("listener resource not found")
}

func setExternalAuthLifecycleExtProcRouteDisabled(t *testing.T, cec *ciliumv2.CiliumEnvoyConfig, filterName string, disabled bool) {
	t.Helper()
	for i := range cec.Spec.Resources {
		resource := &cec.Spec.Resources[i]
		if resource.GetTypeUrl() != envoy.RouteTypeURL {
			continue
		}
		routeConfig := &routeV3.RouteConfiguration{}
		require.NoError(t, proto.Unmarshal(resource.GetValue(), routeConfig))
		route := routeConfig.GetVirtualHosts()[0].GetRoutes()[0]
		if route.TypedPerFilterConfig == nil {
			route.TypedPerFilterConfig = map[string]*anypb.Any{}
		}
		route.TypedPerFilterConfig[filterName] = extProcRouteFilterConfig(disabled)
		value, err := proto.Marshal(routeConfig)
		require.NoError(t, err)
		resource.Value = value
		return
	}
	t.Fatal("route configuration resource not found")
}

func externalAuthLifecycleCEC(t *testing.T, withSelector bool, filterNames []string, routeFilters map[string]bool) *ciliumv2.CiliumEnvoyConfig {
	t.Helper()

	httpFilters := make([]*hcmV3.HttpFilter, 0, len(filterNames)+1)
	if withSelector {
		httpFilters = append(httpFilters, &hcmV3.HttpFilter{Name: extAuthzRouteMetadataFilterName})
	}
	for _, name := range filterNames {
		httpFilters = append(httpFilters, &hcmV3.HttpFilter{Name: name})
	}
	hcm := &hcmV3.HttpConnectionManager{HttpFilters: httpFilters}
	listener := &listenerV3.Listener{
		Name: "listener",
		FilterChains: []*listenerV3.FilterChain{{
			Filters: []*listenerV3.Filter{{
				Name: httpConnectionManagerType,
				ConfigType: &listenerV3.Filter_TypedConfig{
					TypedConfig: toAny(hcm),
				},
			}},
		}},
	}

	typedPerFilterConfig := make(map[string]*anypb.Any, len(routeFilters))
	for name, disabled := range routeFilters {
		typedPerFilterConfig[name] = toAny(&extauthzV3.ExtAuthzPerRoute{
			Override: &extauthzV3.ExtAuthzPerRoute_Disabled{Disabled: disabled},
		})
	}
	routeConfig := &routeV3.RouteConfiguration{
		Name: "routes",
		VirtualHosts: []*routeV3.VirtualHost{{
			Name:    "all",
			Domains: []string{"*"},
			Routes: []*routeV3.Route{{
				TypedPerFilterConfig: typedPerFilterConfig,
			}},
		}},
	}

	listenerResource, err := toXdsResource(listener, envoy.ListenerTypeURL)
	require.NoError(t, err)
	routeResource, err := toXdsResource(routeConfig, envoy.RouteTypeURL)
	require.NoError(t, err)
	return &ciliumv2.CiliumEnvoyConfig{Spec: ciliumv2.CiliumEnvoyConfigSpec{
		Resources: []ciliumv2.XDSResource{listenerResource, routeResource},
	}}
}

func requireExternalAuthVirtualHostDisabled(t *testing.T, cec *ciliumv2.CiliumEnvoyConfig, filterName string, want bool) {
	t.Helper()
	entry, ok := externalAuthLifecycleVirtualHost(t, cec).GetTypedPerFilterConfig()[filterName]
	require.True(t, ok, "missing virtual-host configuration for %s", filterName)
	perRoute := &extauthzV3.ExtAuthzPerRoute{}
	require.NoError(t, entry.UnmarshalTo(perRoute))
	require.Equal(t, want, perRoute.GetDisabled())
}

func requireExternalAuthVirtualHostMissing(t *testing.T, cec *ciliumv2.CiliumEnvoyConfig, filterName string) {
	t.Helper()
	require.NotContains(t, externalAuthLifecycleVirtualHost(t, cec).GetTypedPerFilterConfig(), filterName)
}

func externalAuthLifecycleRouteSelection(t *testing.T, cec *ciliumv2.CiliumEnvoyConfig) string {
	t.Helper()
	route := externalAuthLifecycleVirtualHost(t, cec).GetRoutes()[0]
	return route.GetMetadata().GetFilterMetadata()[extAuthzRouteMetadataFilterName].GetFields()[extAuthzMetadataSelectedKey].GetStringValue()
}

func externalAuthLifecycleVirtualHost(t *testing.T, cec *ciliumv2.CiliumEnvoyConfig) *routeV3.VirtualHost {
	t.Helper()
	for _, resource := range cec.Spec.Resources {
		if resource.GetTypeUrl() != envoy.RouteTypeURL {
			continue
		}
		routeConfig := &routeV3.RouteConfiguration{}
		require.NoError(t, proto.Unmarshal(resource.GetValue(), routeConfig))
		return routeConfig.GetVirtualHosts()[0]
	}
	t.Fatal("route configuration resource not found")
	return nil
}

func requireExternalAuthPerRouteDisabled(t *testing.T, cec *ciliumv2.CiliumEnvoyConfig, filterName string, want bool) {
	t.Helper()
	for _, resource := range cec.Spec.Resources {
		if resource.GetTypeUrl() != envoy.RouteTypeURL {
			continue
		}
		routeConfig := &routeV3.RouteConfiguration{}
		require.NoError(t, proto.Unmarshal(resource.GetValue(), routeConfig))
		virtualHost := routeConfig.GetVirtualHosts()[0]
		entry, ok := virtualHost.GetRoutes()[0].GetTypedPerFilterConfig()[filterName]
		if !ok {
			entry, ok = virtualHost.GetTypedPerFilterConfig()[filterName]
		}
		require.True(t, ok, "missing per-route configuration for %s", filterName)
		perRoute := &extauthzV3.ExtAuthzPerRoute{}
		require.NoError(t, entry.UnmarshalTo(perRoute))
		require.Equal(t, want, perRoute.GetDisabled())
		return
	}
	t.Fatal("route configuration resource not found")
}

func requireExternalAuthExtProcDisabled(t *testing.T, route *routeV3.Route, filterName string) {
	t.Helper()
	requireExternalAuthExtProcState(t, route, filterName, true)
}

func requireExternalAuthExtProcEnabled(t *testing.T, route *routeV3.Route, filterName string) {
	t.Helper()
	requireExternalAuthExtProcState(t, route, filterName, false)
}

func requireExternalAuthExtProcState(t *testing.T, route *routeV3.Route, filterName string, disabled bool) {
	t.Helper()
	entry, ok := route.GetTypedPerFilterConfig()[filterName]
	require.True(t, ok, "missing per-route configuration for %s", filterName)
	filterConfig := &routeV3.FilterConfig{}
	require.NoError(t, entry.UnmarshalTo(filterConfig))
	require.Equal(t, disabled, filterConfig.GetDisabled())
	if disabled {
		require.Nil(t, filterConfig.GetConfig())
		return
	}
	perRoute := &extprocv3.ExtProcPerRoute{}
	require.NoError(t, filterConfig.GetConfig().UnmarshalTo(perRoute))
	require.NotNil(t, perRoute.GetOverrides())
	require.NoError(t, perRoute.ValidateAll())
}
