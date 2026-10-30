// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"fmt"
	"sort"
	"strings"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerV3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routeV3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	extauthzV3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	hcmV3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_type_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

// RetainExternalAuthFilterTombstones carries the bounded pre-selector ext_authz
// filter set into newer RDS generations as disabled virtual-host overrides.
// Current routes explicitly override their selected filter, while older HCMs
// keep unrelated and removed filters disabled as their connections drain.
func RetainExternalAuthFilterTombstones(existing, desired *ciliumv2.CiliumEnvoyConfig) error {
	if existing == nil || desired == nil {
		return nil
	}

	previous, err := externalAuthLifecycleStateFromCEC(existing)
	if err != nil {
		return fmt.Errorf("extracting existing external authorization lifecycle: %w", err)
	}
	current, err := externalAuthLifecycleStateFromCEC(desired)
	if err != nil {
		return fmt.Errorf("extracting desired external authorization lifecycle: %w", err)
	}

	tombstones := previous.tombstones
	// Seed the complete pre-selector filter set as a disabled baseline. Routes
	// selecting a baseline filter explicitly enable it; routes selecting a new
	// filter retain their generation fallback until a selector-capable HCM runs.
	if !previous.hasSelector {
		for name := range previous.listenerFilters {
			tombstones[name] = struct{}{}
		}
	}
	retainedExtProcFilters := previous.retainedExtProcFilters
	if current.hasFallback || len(previous.listenerFilters) > 0 {
		for name := range previous.legacyExtProcFilters {
			retainedExtProcFilters[name] = struct{}{}
		}
	}

	retainDisabledSelection := previous.hasDisabledSelection ||
		(previous.hasSelector && len(current.listenerFilters) == 0)
	if len(tombstones) == 0 && len(retainedExtProcFilters) == 0 && !retainDisabledSelection {
		return nil
	}

	tombstoneNames := make([]string, 0, len(tombstones))
	for name := range tombstones {
		tombstoneNames = append(tombstoneNames, name)
	}
	sort.Strings(tombstoneNames)
	disabled := toAny(&extauthzV3.ExtAuthzPerRoute{
		Override: &extauthzV3.ExtAuthzPerRoute_Disabled{Disabled: true},
	})

	for i := range desired.Spec.Resources {
		resource := &desired.Spec.Resources[i]
		if resource.GetTypeUrl() != envoy.RouteTypeURL {
			continue
		}

		routeConfig := &routeV3.RouteConfiguration{}
		if err := proto.Unmarshal(resource.GetValue(), routeConfig); err != nil {
			return fmt.Errorf("unmarshalling desired route configuration %q: %w", resource.GetTypeUrl(), err)
		}
		for _, virtualHost := range routeConfig.GetVirtualHosts() {
			if len(tombstoneNames) > 0 && virtualHost.TypedPerFilterConfig == nil {
				virtualHost.TypedPerFilterConfig = make(map[string]*anypb.Any, len(tombstoneNames))
			}
			for _, name := range tombstoneNames {
				if _, exists := virtualHost.TypedPerFilterConfig[name]; !exists {
					virtualHost.TypedPerFilterConfig[name] = proto.Clone(disabled).(*anypb.Any)
				}
			}
			if retainDisabledSelection && len(current.listenerFilters) == 0 {
				for _, route := range virtualHost.GetRoutes() {
					route.Metadata = externalAuthRouteMetadata(extAuthzDisabledFilterID)
				}
			}
			var err error
			virtualHost.Routes, err = unlockExternalAuthRouteGates(virtualHost.GetRoutes(), tombstones)
			if err != nil {
				return fmt.Errorf("unlocking external authorization route gates: %w", err)
			}
			retainExternalAuthExtProcState(virtualHost.GetRoutes(), retainedExtProcFilters)
			disableRetainedExternalAuthExtProcFilters(
				virtualHost.GetRoutes(), retainedExtProcFilters, current.listenerExtProcFilters,
			)
		}
		value, err := proto.Marshal(routeConfig)
		if err != nil {
			return fmt.Errorf("marshalling desired route configuration %q: %w", routeConfig.GetName(), err)
		}
		resource.Value = value
	}

	return nil
}

type externalAuthLifecycleState struct {
	listenerFilters        map[string]struct{}
	listenerExtProcFilters map[string]struct{}
	legacyExtProcFilters   map[string]struct{}
	tombstones             map[string]struct{}
	retainedExtProcFilters map[string]struct{}
	hasSelector            bool
	hasDisabledSelection   bool
	hasFallback            bool
}

func externalAuthLifecycleStateFromCEC(cec *ciliumv2.CiliumEnvoyConfig) (externalAuthLifecycleState, error) {
	state := externalAuthLifecycleState{
		listenerFilters:        map[string]struct{}{},
		listenerExtProcFilters: map[string]struct{}{},
		legacyExtProcFilters:   map[string]struct{}{},
		tombstones:             map[string]struct{}{},
		retainedExtProcFilters: map[string]struct{}{},
	}
	for _, resource := range cec.Spec.Resources {
		switch resource.GetTypeUrl() {
		case envoy.ListenerTypeURL:
			listener := &listenerV3.Listener{}
			if err := proto.Unmarshal(resource.GetValue(), listener); err != nil {
				return externalAuthLifecycleState{}, fmt.Errorf("unmarshalling listener: %w", err)
			}
			for _, filterChain := range listener.GetFilterChains() {
				for _, networkFilter := range filterChain.GetFilters() {
					typedConfig := networkFilter.GetTypedConfig()
					if typedConfig.GetTypeUrl() != envoy.HttpConnectionManagerTypeURL {
						continue
					}
					hcm := &hcmV3.HttpConnectionManager{}
					if err := typedConfig.UnmarshalTo(hcm); err != nil {
						return externalAuthLifecycleState{}, fmt.Errorf("unmarshalling HTTP connection manager: %w", err)
					}
					for _, httpFilter := range hcm.GetHttpFilters() {
						if httpFilter.GetName() == extAuthzRouteMetadataFilterName {
							state.hasSelector = true
						}
						if isExternalAuthFilterName(httpFilter.GetName()) {
							state.listenerFilters[httpFilter.GetName()] = struct{}{}
						}
						if isExternalAuthExtProcFilterName(httpFilter.GetName()) {
							state.listenerExtProcFilters[httpFilter.GetName()] = struct{}{}
							if !httpFilter.GetDisabled() {
								state.legacyExtProcFilters[httpFilter.GetName()] = struct{}{}
							}
						}
					}
				}
			}
		case envoy.RouteTypeURL:
			routeConfig := &routeV3.RouteConfiguration{}
			if err := proto.Unmarshal(resource.GetValue(), routeConfig); err != nil {
				return externalAuthLifecycleState{}, fmt.Errorf("unmarshalling route configuration: %w", err)
			}
			for _, virtualHost := range routeConfig.GetVirtualHosts() {
				if err := addExternalAuthTombstones(state.tombstones, virtualHost.GetTypedPerFilterConfig()); err != nil {
					return externalAuthLifecycleState{}, err
				}
				for _, route := range virtualHost.GetRoutes() {
					metadata := route.GetMetadata().GetFilterMetadata()[extAuthzRouteMetadataFilterName]
					selected := metadata.GetFields()[extAuthzMetadataSelectedKey].GetStringValue()
					if selected == extAuthzDisabledFilterID {
						state.hasDisabledSelection = true
					}
					if metadata.GetFields()[extAuthzMetadataFallbackKey].GetBoolValue() {
						state.hasFallback = true
					}
					for name := range metadata.GetFields()[extAuthzMetadataExtProcStateKey].GetStructValue().GetFields() {
						state.retainedExtProcFilters[name] = struct{}{}
					}
				}
			}
		}
	}
	return state, nil
}

func addExternalAuthTombstones(result map[string]struct{}, configs map[string]*anypb.Any) error {
	for name, config := range configs {
		if !isExternalAuthFilterName(name) {
			continue
		}
		perRoute := &extauthzV3.ExtAuthzPerRoute{}
		if err := config.UnmarshalTo(perRoute); err != nil {
			return fmt.Errorf("unmarshalling external authorization tombstone %q: %w", name, err)
		}
		if perRoute.GetDisabled() {
			result[name] = struct{}{}
		}
	}
	return nil
}

func unlockExternalAuthRouteGates(routes []*routeV3.Route, baseline map[string]struct{}) ([]*routeV3.Route, error) {
	result := make([]*routeV3.Route, 0, len(routes))
	for i := 0; i < len(routes); i++ {
		route := routes[i]
		if !hasExternalAuthGenerationMatcher(route) {
			result = append(result, route)
			continue
		}

		filterName, err := enabledExternalAuthFilterName(route)
		if err != nil {
			return nil, err
		}
		if _, exists := baseline[filterName]; !exists {
			result = append(result, route)
			continue
		}

		matchers := route.GetMatch().GetDynamicMetadata()
		kept := matchers[:0]
		for _, matcher := range matchers {
			if !isExternalAuthGenerationMatcher(matcher) {
				kept = append(kept, matcher)
			}
		}
		route.Match.DynamicMetadata = kept
		result = append(result, route)
		if i+1 < len(routes) && isExternalAuthFallbackRoute(routes[i+1]) {
			i++
		}
	}
	return result, nil
}

func enabledExternalAuthFilterName(route *routeV3.Route) (string, error) {
	for name, config := range route.GetTypedPerFilterConfig() {
		if !isExternalAuthFilterName(name) {
			continue
		}
		perRoute := &extauthzV3.ExtAuthzPerRoute{}
		if err := config.UnmarshalTo(perRoute); err != nil {
			return "", fmt.Errorf("unmarshalling external authorization route config %q: %w", name, err)
		}
		if disabled, ok := perRoute.GetOverride().(*extauthzV3.ExtAuthzPerRoute_Disabled); ok && !disabled.Disabled {
			return name, nil
		}
	}
	return "", nil
}

func hasExternalAuthGenerationMatcher(route *routeV3.Route) bool {
	for _, matcher := range route.GetMatch().GetDynamicMetadata() {
		if isExternalAuthGenerationMatcher(matcher) {
			return true
		}
	}
	return false
}

func isExternalAuthGenerationMatcher(matcher *envoy_type_matcher_v3.MetadataMatcher) bool {
	return matcher.GetFilter() == extAuthzDynamicMetadataName &&
		len(matcher.GetPath()) == 1 &&
		matcher.GetPath()[0].GetKey() == extAuthzMetadataSelectedKey
}

func isExternalAuthFallbackRoute(route *routeV3.Route) bool {
	metadata := route.GetMetadata().GetFilterMetadata()[extAuthzRouteMetadataFilterName]
	return metadata.GetFields()[extAuthzMetadataFallbackKey].GetBoolValue()
}

func retainExternalAuthExtProcState(routes []*routeV3.Route, retained map[string]struct{}) {
	if len(routes) == 0 || len(retained) == 0 {
		return
	}
	route := routes[0]
	if route.Metadata == nil {
		route.Metadata = &envoy_config_core_v3.Metadata{}
	}
	if route.Metadata.FilterMetadata == nil {
		route.Metadata.FilterMetadata = map[string]*structpb.Struct{}
	}
	metadata := route.Metadata.FilterMetadata[extAuthzRouteMetadataFilterName]
	if metadata == nil {
		metadata = &structpb.Struct{Fields: map[string]*structpb.Value{}}
		route.Metadata.FilterMetadata[extAuthzRouteMetadataFilterName] = metadata
	}
	if metadata.Fields == nil {
		metadata.Fields = map[string]*structpb.Value{}
	}
	fields := make(map[string]*structpb.Value, len(retained))
	for name := range retained {
		fields[name] = structpb.NewBoolValue(true)
	}
	metadata.Fields[extAuthzMetadataExtProcStateKey] = structpb.NewStructValue(&structpb.Struct{Fields: fields})
}

func disableRetainedExternalAuthExtProcFilters(routes []*routeV3.Route, retained, current map[string]struct{}) {
	if len(retained) == 0 {
		return
	}
	disabled := extProcRouteFilterConfig(true)
	for _, route := range routes {
		fallback := isExternalAuthFallbackRoute(route)
		for name := range retained {
			if !fallback {
				if _, active := current[name]; active {
					continue
				}
			}
			if route.TypedPerFilterConfig == nil {
				route.TypedPerFilterConfig = make(map[string]*anypb.Any)
			}
			route.TypedPerFilterConfig[name] = proto.Clone(disabled).(*anypb.Any)
		}
	}
}

func isExternalAuthFilterName(name string) bool {
	return strings.HasPrefix(name, ExtAuthzFilterNamePrefix+"/")
}

func isExternalAuthExtProcFilterName(name string) bool {
	return strings.HasPrefix(name, ExtProcFilterNamePrefix+"/")
}
