// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"regexp"
	"testing"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	httpCORSv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/cors/v3"
	extauthzv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	luav3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	statefulsessionv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/stateful_session/v3"
	httpConnectionManagerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	cookiev3 "github.com/envoyproxy/go-control-plane/envoy/extensions/http/stateful_session/cookie/v3"
	envoy_type_http_v3 "github.com/envoyproxy/go-control-plane/envoy/type/http/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/cilium/cilium/operator/pkg/model"
)

func Test_desiredHTTPConnectionManager(t *testing.T) {
	t.Run("no CORS filter enabled", func(t *testing.T) {
		i := &cecTranslator{}
		m := &model.Model{}
		res, err := i.desiredHTTPConnectionManager("dummy-name", "dummy-route-name", m)
		require.NoError(t, err)

		httpConnectionManager := &httpConnectionManagerv3.HttpConnectionManager{}
		err = proto.Unmarshal(res.Value, httpConnectionManager)

		require.NoError(t, err)

		require.Equal(t, "dummy-name", httpConnectionManager.StatPrefix)
		require.Equal(t, &httpConnectionManagerv3.HttpConnectionManager_Rds{
			Rds: &httpConnectionManagerv3.Rds{RouteConfigName: "dummy-route-name"},
		}, httpConnectionManager.GetRouteSpecifier())

		require.Len(t, httpConnectionManager.GetHttpFilters(), 3)
		require.Equal(t, "envoy.filters.http.grpc_web", httpConnectionManager.GetHttpFilters()[0].Name)
		require.Equal(t, "envoy.filters.http.grpc_stats", httpConnectionManager.GetHttpFilters()[1].Name)
		require.Equal(t, "envoy.filters.http.router", httpConnectionManager.GetHttpFilters()[2].Name)

		require.Len(t, httpConnectionManager.GetUpgradeConfigs(), 1)
		require.Equal(t, "websocket", httpConnectionManager.GetUpgradeConfigs()[0].UpgradeType)
	})
	t.Run("CORS filter enabled", func(t *testing.T) {
		i := &cecTranslator{}
		m := &model.Model{HTTP: []model.HTTPListener{
			{
				Routes: []model.HTTPRoute{
					{
						CORS: &model.HTTPCORSFilter{AllowOrigins: []string{"*"}},
					},
				},
			},
		}}
		res, err := i.desiredHTTPConnectionManager("dummy-name", "dummy-route-name", m)
		require.NoError(t, err)

		httpConnectionManager := &httpConnectionManagerv3.HttpConnectionManager{}
		err = proto.Unmarshal(res.Value, httpConnectionManager)

		require.NoError(t, err)

		require.Equal(t, "dummy-name", httpConnectionManager.StatPrefix)
		require.Equal(t, &httpConnectionManagerv3.HttpConnectionManager_Rds{
			Rds: &httpConnectionManagerv3.Rds{RouteConfigName: "dummy-route-name"},
		}, httpConnectionManager.GetRouteSpecifier())

		require.Len(t, httpConnectionManager.GetHttpFilters(), 4)
		require.Equal(t, "envoy.filters.http.grpc_web", httpConnectionManager.GetHttpFilters()[0].Name)
		require.Equal(t, "envoy.filters.http.grpc_stats", httpConnectionManager.GetHttpFilters()[1].Name)
		require.Equal(t, "envoy.filters.http.cors", httpConnectionManager.GetHttpFilters()[2].Name)
		require.Equal(t, "envoy.filters.http.router", httpConnectionManager.GetHttpFilters()[3].Name)

		require.Len(t, httpConnectionManager.GetUpgradeConfigs(), 1)
		require.Equal(t, "websocket", httpConnectionManager.GetUpgradeConfigs()[0].UpgradeType)
	})
	t.Run("access logs configured", func(t *testing.T) {
		i := &cecTranslator{}
		m := &model.Model{
			Telemetry: &model.Telemetry{
				AccessLogs: map[model.AccessLogsTarget][]model.AccessLogs{
					model.AccessLogsTargetHTTP: {
						{
							Format: model.AccessLogsFormatText,
							Text:   "%REQ(:METHOD)% %RESPONSE_CODE%",
						},
					},
				},
			},
		}
		res, err := i.desiredHTTPConnectionManager("dummy-name", "dummy-route-name", m)
		require.NoError(t, err)

		httpConnectionManager := &httpConnectionManagerv3.HttpConnectionManager{}
		err = proto.Unmarshal(res.Value, httpConnectionManager)
		require.NoError(t, err)

		require.Len(t, httpConnectionManager.GetAccessLog(), 1)
		require.Equal(t, "envoy.access_loggers.stdout", httpConnectionManager.GetAccessLog()[0].GetName())
	})
}

func Test_getHTTPConnectionManagerHttpFilters(t *testing.T) {
	t.Run("no CORS filter enabled", func(t *testing.T) {
		m := &model.Model{}
		i := &cecTranslator{}
		res := i.getHTTPConnectionManagerHttpFilters(m)

		require.Len(t, res, 3)
		require.Equal(t, "envoy.filters.http.grpc_web", res[0].Name)
		require.Equal(t, "envoy.filters.http.grpc_stats", res[1].Name)
		require.Equal(t, "envoy.filters.http.router", res[2].Name)
	})
	t.Run("CORS filter enabled", func(t *testing.T) {
		m := &model.Model{HTTP: []model.HTTPListener{
			{
				Routes: []model.HTTPRoute{
					{
						CORS: &model.HTTPCORSFilter{AllowOrigins: []string{"*"}},
					},
				},
			},
		}}
		i := &cecTranslator{}
		res := i.getHTTPConnectionManagerHttpFilters(m)

		require.Len(t, res, 4)
		require.Equal(t, "envoy.filters.http.grpc_web", res[0].Name)
		require.Equal(t, "envoy.filters.http.grpc_stats", res[1].Name)
		require.Equal(t, "envoy.filters.http.cors", res[2].Name)
		require.Equal(t, "envoy.filters.http.router", res[3].Name)

	})
	t.Run("stateful session filter enabled", func(t *testing.T) {
		m := &model.Model{HTTP: []model.HTTPListener{
			{
				Routes: []model.HTTPRoute{
					{
						SessionPersistence: &model.HTTPSessionPersistence{
							Cookie: &model.HTTPCookieSessionPersistence{},
						},
					},
				},
			},
		}}
		i := &cecTranslator{}
		res := i.getHTTPConnectionManagerHttpFilters(m)

		require.Len(t, res, 4)
		require.Equal(t, "envoy.filters.http.grpc_web", res[0].Name)
		require.Equal(t, "envoy.filters.http.grpc_stats", res[1].Name)
		require.Equal(t, "envoy.filters.http.stateful_session", res[2].Name)
		require.Equal(t, "envoy.filters.http.router", res[3].Name)

	})
}

func Test_desiredHTTPConnectionManager_withExtAuthz(t *testing.T) {
	i := &cecTranslator{}
	m := &model.Model{
		HTTP: []model.HTTPListener{{
			Routes: []model.HTTPRoute{
				{
					ExternalAuth: &model.HTTPExternalAuthFilter{
						Backend:  model.Backend{Name: "grpc-authz", Namespace: "default", Port: &model.BackendPort{Port: 9000}},
						Protocol: model.ExternalAuthProtocolGRPC,
					},
				},
				{
					ExternalAuth: &model.HTTPExternalAuthFilter{
						Backend:    model.Backend{Name: "http-authz", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
						Protocol:   model.ExternalAuthProtocolHTTP,
						PathPrefix: "/auth",
					},
				},
			},
		}},
	}
	authFilters := i.getUniqueAuthFilters(m)
	res, err := i.desiredHTTPConnectionManager("dummy-name", "dummy-route-name", m)
	require.NoError(t, err)

	hcm := &httpConnectionManagerv3.HttpConnectionManager{}
	require.NoError(t, proto.Unmarshal(res.Value, hcm))

	// grpc_web, grpc_stats, route metadata, ext_authz/grpc, ext_authz/http, router
	require.Len(t, hcm.GetHttpFilters(), 6)
	require.Equal(t, "envoy.filters.http.grpc_web", hcm.GetHttpFilters()[0].Name)
	require.Equal(t, "envoy.filters.http.grpc_stats", hcm.GetHttpFilters()[1].Name)
	require.Equal(t, "io.cilium.external_auth.route_metadata", hcm.GetHttpFilters()[2].Name)
	require.Equal(t, ExtAuthzFilterName(extAuthzFilterKey(authFilters[0])), hcm.GetHttpFilters()[3].Name)
	require.Equal(t, ExtAuthzFilterName(extAuthzFilterKey(authFilters[1])), hcm.GetHttpFilters()[4].Name)
	require.Equal(t, "envoy.filters.http.router", hcm.GetHttpFilters()[5].Name)

	routeMetadataFilter := &luav3.Lua{}
	require.NoError(t, proto.Unmarshal(hcm.GetHttpFilters()[2].GetTypedConfig().Value, routeMetadataFilter))
	routeMetadataScript := routeMetadataFilter.GetDefaultSourceCode().GetInlineString()
	require.Contains(t, routeMetadataScript, "local selected_filter = \"!legacy\"", "older route resources must remain authorized during an LDS-first update")
	require.Contains(t, routeMetadataScript, "local available_filters = {")
	require.Contains(t, routeMetadataScript, "route_metadata:get(\"selected_filter\")")
	require.Contains(t, routeMetadataScript, "configured == \"!disabled\" or available_filters[configured]")
	require.Contains(t, routeMetadataScript, "elseif configured ~= nil then")
	require.Contains(t, routeMetadataScript, "request_handle:respond({[\":status\"] = \"503\"}, \"\")", "a route selecting a filter absent from a retained listener must stop locally")
	require.Contains(t, routeMetadataScript, "request_handle:clearRouteCache()", "the selected filter must unlock the authenticated route")
	for _, authFilter := range authFilters {
		require.Contains(t, routeMetadataScript, "[\""+testExtAuthzFilterID(authFilter)+"\"] = true")
	}
	require.Contains(t, routeMetadataScript, "dynamicMetadata():set")

	// Verify GRPC filter points to the right cluster
	grpcFilter := &extauthzv3.ExtAuthz{}
	require.NoError(t, proto.Unmarshal(hcm.GetHttpFilters()[3].GetTypedConfig().Value, grpcFilter))
	require.NotNil(t, grpcFilter.GetGrpcService())
	require.Equal(t, "grpc:default:grpc-authz:9000", grpcFilter.GetGrpcService().GetEnvoyGrpc().GetClusterName())

	// Verify HTTP filter has path prefix
	httpFilter := &extauthzv3.ExtAuthz{}
	require.NoError(t, proto.Unmarshal(hcm.GetHttpFilters()[4].GetTypedConfig().Value, httpFilter))
	require.NotNil(t, httpFilter.GetHttpService())
	require.Equal(t, "/auth", httpFilter.GetHttpService().GetPathPrefix())
	require.Equal(t, "http:default:http-authz:8080", httpFilter.GetHttpService().GetServerUri().GetCluster())
}

func TestExternalAuthFilterLifecycle(t *testing.T) {
	authFilter := &model.HTTPExternalAuthFilter{
		Backend:               model.Backend{Name: "authz", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
		Protocol:              model.ExternalAuthProtocolHTTP,
		AllowedRequestHeaders: []string{"X-Tenant", "Cookie"},
	}
	filterName := ExtAuthzFilterName(extAuthzFilterKey(authFilter))

	filter := buildExtAuthzHTTPFilter(authFilter)
	require.False(t, filter.GetDisabled(), "ExternalAuth filters must remain active for compatibility with older route resources")

	config := &extauthzv3.ExtAuthz{}
	require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
	require.Equal(t, "io.cilium.external_auth", config.GetFilterEnabledMetadata().GetFilter())
	require.Len(t, config.GetFilterEnabledMetadata().GetPath(), 1)
	require.Equal(t, "selected_filter", config.GetFilterEnabledMetadata().GetPath()[0].GetKey())
	require.False(t, config.GetFilterEnabledMetadata().GetInvert())
	require.Equal(t, []string{"!legacy", testExtAuthzFilterID(authFilter)}, extAuthzMetadataMatcherValues(config))
	require.Equal(t, []string{"Cookie", "X-Tenant"}, []string{
		config.GetAllowedHeaders().GetPatterns()[0].GetExact(),
		config.GetAllowedHeaders().GetPatterns()[1].GetExact(),
	})

	activeConfig := getTypedPerFilterConfig(authFilter, []*model.HTTPExternalAuthFilter{authFilter}, nil, nil, model.HTTPRoute{}, false)
	activeEntry, ok := activeConfig[filterName]
	require.True(t, ok, "the authenticated route must explicitly retain its selected filter")
	activePerRoute := &extauthzv3.ExtAuthzPerRoute{}
	require.NoError(t, proto.Unmarshal(activeEntry.Value, activePerRoute))
	require.False(t, activePerRoute.GetDisabled())

	unauthenticatedConfig := getTypedPerFilterConfig(nil, nil, nil, nil, model.HTTPRoute{}, false)
	require.NotContains(t, unauthenticatedConfig, filterName, "a route without current ExternalAuth filters has no per-filter override")

	reordered := *authFilter
	reordered.AllowedRequestHeaders = []string{"Cookie", "X-Tenant"}
	require.True(t, proto.Equal(filter, buildExtAuthzHTTPFilter(&reordered)), "equivalent header sets must emit the same HCM filter")
}

func Test_buildExtAuthzHTTPFilter_forwardBody(t *testing.T) {
	t.Run("forward body set on GRPC filter", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:     model.Backend{Name: "grpc-authz", Namespace: "default", Port: &model.BackendPort{Port: 9000}},
			Protocol:    model.ExternalAuthProtocolGRPC,
			ForwardBody: &model.ForwardBodyConfig{MaxSize: 4096},
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.NotNil(t, config.GetWithRequestBody())
		require.Equal(t, uint32(4096), config.GetWithRequestBody().GetMaxRequestBytes())
		require.True(t, config.GetWithRequestBody().GetAllowPartialMessage())
	})

	t.Run("forward body set on HTTP filter", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:     model.Backend{Name: "http-authz", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
			Protocol:    model.ExternalAuthProtocolHTTP,
			ForwardBody: &model.ForwardBodyConfig{MaxSize: 8192},
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.NotNil(t, config.GetWithRequestBody())
		require.Equal(t, uint32(8192), config.GetWithRequestBody().GetMaxRequestBytes())
		require.True(t, config.GetWithRequestBody().GetAllowPartialMessage())
	})

	t.Run("no forward body when nil", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:  model.Backend{Name: "http-authz", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
			Protocol: model.ExternalAuthProtocolHTTP,
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.Nil(t, config.GetWithRequestBody())
	})

	t.Run("no forward body when max size is zero", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:     model.Backend{Name: "http-authz", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
			Protocol:    model.ExternalAuthProtocolHTTP,
			ForwardBody: &model.ForwardBodyConfig{MaxSize: 0},
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.Nil(t, config.GetWithRequestBody())
	})
}

func Test_buildExtAuthzHTTPFilter_decoderHeaderMutationRules(t *testing.T) {
	for _, tc := range []struct {
		name     string
		protocol model.ExternalAuthProtocol
	}{
		{name: "HTTP", protocol: model.ExternalAuthProtocolHTTP},
		{name: "GRPC", protocol: model.ExternalAuthProtocolGRPC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			af := &model.HTTPExternalAuthFilter{
				Backend:  model.Backend{Name: "authz", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
				Protocol: tc.protocol,
			}
			filter := buildExtAuthzHTTPFilter(af)
			config := &extauthzv3.ExtAuthz{}
			require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))

			expr := config.GetDecoderHeaderMutationRules().GetDisallowExpression().GetRegex()
			require.Equal(t, "^(:authority|host|content-length)$", expr)
			_, err := regexp.Compile(expr)
			require.NoError(t, err)
		})
	}
}

func Test_buildExtAuthzHTTPFilter_allowedRequestHeaders(t *testing.T) {
	// Per the Gateway API spec: if AllowedRequestHeaders is empty, all headers must be sent.
	// We achieve this by leaving AllowedHeaders unset; Envoy then forwards all headers by default.
	t.Run("GRPC empty list forwards all headers (spec: empty means send all)", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:               model.Backend{Name: "grpc-authz", Namespace: "default", Port: &model.BackendPort{Port: 9000}},
			Protocol:              model.ExternalAuthProtocolGRPC,
			AllowedRequestHeaders: []string{},
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.Nil(t, config.GetAllowedHeaders())
	})

	t.Run("GRPC nil list forwards all headers (spec: empty means send all)", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:  model.Backend{Name: "grpc-authz", Namespace: "default", Port: &model.BackendPort{Port: 9000}},
			Protocol: model.ExternalAuthProtocolGRPC,
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.Nil(t, config.GetAllowedHeaders())
	})

	t.Run("GRPC explicit headers forwarded", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:               model.Backend{Name: "grpc-authz", Namespace: "default", Port: &model.BackendPort{Port: 9000}},
			Protocol:              model.ExternalAuthProtocolGRPC,
			AllowedRequestHeaders: []string{"X-Custom-Header", "X-Tenant-ID"},
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.NotNil(t, config.GetAllowedHeaders())
		require.Len(t, config.GetAllowedHeaders().GetPatterns(), 2)
		require.Equal(t, "X-Custom-Header", config.GetAllowedHeaders().GetPatterns()[0].GetExact())
		require.Equal(t, "X-Tenant-ID", config.GetAllowedHeaders().GetPatterns()[1].GetExact())
	})

	t.Run("HTTP empty list produces no AllowedHeaders (Envoy rejects empty matcher)", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:               model.Backend{Name: "http-authz", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
			Protocol:              model.ExternalAuthProtocolHTTP,
			AllowedRequestHeaders: []string{},
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.Nil(t, config.GetAllowedHeaders())
	})

	t.Run("HTTP explicit headers forwarded", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:               model.Backend{Name: "http-authz", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
			Protocol:              model.ExternalAuthProtocolHTTP,
			AllowedRequestHeaders: []string{"X-Custom-Header"},
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.NotNil(t, config.GetAllowedHeaders())
		require.Len(t, config.GetAllowedHeaders().GetPatterns(), 1)
		require.Equal(t, "X-Custom-Header", config.GetAllowedHeaders().GetPatterns()[0].GetExact())
	})
}

func Test_getTypedPerFilterConfig(t *testing.T) {
	authFilters := []*model.HTTPExternalAuthFilter{
		{Backend: model.Backend{Name: "svc-a", Namespace: "ns", Port: &model.BackendPort{Port: 9000}}, Protocol: model.ExternalAuthProtocolGRPC},
		{Backend: model.Backend{Name: "svc-b", Namespace: "ns", Port: &model.BackendPort{Port: 8080}}, Protocol: model.ExternalAuthProtocolHTTP},
	}

	t.Run("route without auth disables all filters", func(t *testing.T) {
		cfg := getTypedPerFilterConfig(nil, authFilters, nil, nil, model.HTTPRoute{}, false)
		require.Len(t, cfg, 2)
		for _, v := range cfg {
			perRoute := &extauthzv3.ExtAuthzPerRoute{}
			require.NoError(t, proto.Unmarshal(v.Value, perRoute))
			require.True(t, perRoute.GetDisabled())
		}
	})

	t.Run("route with auth enables its filter and disables others", func(t *testing.T) {
		routeAuth := &model.HTTPExternalAuthFilter{
			Backend:  model.Backend{Name: "svc-a", Namespace: "ns", Port: &model.BackendPort{Port: 9000}},
			Protocol: model.ExternalAuthProtocolGRPC,
		}
		cfg := getTypedPerFilterConfig(routeAuth, authFilters, nil, nil, model.HTTPRoute{}, false)
		require.Len(t, cfg, 2)
		activeEntry, hasSvcA := cfg[ExtAuthzFilterName(extAuthzFilterKey(authFilters[0]))]
		require.True(t, hasSvcA)
		activePerRoute := &extauthzv3.ExtAuthzPerRoute{}
		require.NoError(t, proto.Unmarshal(activeEntry.Value, activePerRoute))
		require.False(t, activePerRoute.GetDisabled())
		disabledEntry, hasSvcB := cfg[ExtAuthzFilterName(extAuthzFilterKey(authFilters[1]))]
		require.True(t, hasSvcB)
		perRoute := &extauthzv3.ExtAuthzPerRoute{}
		require.NoError(t, proto.Unmarshal(disabledEntry.Value, perRoute))
		require.True(t, perRoute.GetDisabled())
	})

	t.Run("route with CORS filter", func(t *testing.T) {
		cfg := getTypedPerFilterConfig(nil, nil, nil, nil, model.HTTPRoute{
			CORS: &model.HTTPCORSFilter{MaxAge: 42},
		}, false)
		require.Len(t, cfg, 1)
		cors := &httpCORSv3.CorsPolicy{}
		require.NoError(t, proto.Unmarshal(cfg["envoy.filters.http.cors"].Value, cors))
	})

	t.Run("no auth filters returns nil", func(t *testing.T) {
		require.Nil(t, getTypedPerFilterConfig(nil, nil, nil, nil, model.HTTPRoute{}, false))
	})

	t.Run("route without persistence disables stateful sessions", func(t *testing.T) {
		cfg := getTypedPerFilterConfig(nil, nil, nil, nil, model.HTTPRoute{}, true)
		entry, ok := cfg["envoy.filters.http.stateful_session"]
		require.True(t, ok)
		perRoute := &statefulsessionv3.StatefulSessionPerRoute{}
		require.NoError(t, proto.Unmarshal(entry.Value, perRoute))
		require.True(t, perRoute.GetDisabled())
	})

	t.Run("route with persistence configures cookie session state", func(t *testing.T) {
		cfg := getTypedPerFilterConfig(nil, nil, nil, nil, model.HTTPRoute{
			SessionPersistence: &model.HTTPSessionPersistence{
				Cookie: &model.HTTPCookieSessionPersistence{
					Name: "gateway-session",
					Path: "/api",
				},
			},
		}, true)
		entry, ok := cfg["envoy.filters.http.stateful_session"]
		require.True(t, ok)
		perRoute := &statefulsessionv3.StatefulSessionPerRoute{}
		require.NoError(t, proto.Unmarshal(entry.Value, perRoute))

		want := &statefulsessionv3.StatefulSessionPerRoute{
			Override: &statefulsessionv3.StatefulSessionPerRoute_StatefulSession{
				StatefulSession: &statefulsessionv3.StatefulSession{
					SessionState: &envoy_config_core_v3.TypedExtensionConfig{
						Name: "envoy.http.stateful_session.cookie",
						TypedConfig: toAny(&cookiev3.CookieBasedSessionState{
							Cookie: &envoy_type_http_v3.Cookie{
								Name: "gateway-session",
								Path: "/api",
								Ttl:  durationpb.New(0),
								Attributes: []*envoy_type_http_v3.CookieAttribute{
									{Name: "Secure"},
									{Name: "HttpOnly"},
									{Name: "SameSite", Value: "Strict"},
								},
							},
						}),
					},
					Strict: false,
				},
			},
		}
		if diff := cmp.Diff(want, perRoute, protocmp.Transform()); diff != "" {
			t.Errorf("Stateful session configuration did not match (-want +got):\n%s", diff)
		}
	})
}

func Test_extAuthzFilterKey_sameBackendDifferentConfig(t *testing.T) {
	backend := model.Backend{Name: "authz", Namespace: "ns", Port: &model.BackendPort{Port: 9000}}

	base := &model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP}
	withPrefix := &model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP, PathPrefix: "/check"}
	withBody := &model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP, ForwardBody: &model.ForwardBodyConfig{MaxSize: 1024}}
	withReqHeaders := &model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP, AllowedRequestHeaders: []string{"X-Tenant"}}
	withRespHeaders := &model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP, AllowedResponseHeaders: []string{"X-Authz-Status"}}

	keys := []string{
		extAuthzFilterKey(base),
		extAuthzFilterKey(withPrefix),
		extAuthzFilterKey(withBody),
		extAuthzFilterKey(withReqHeaders),
		extAuthzFilterKey(withRespHeaders),
	}
	// All five configs are distinct — each must produce a unique key.
	seen := map[string]struct{}{}
	for _, k := range keys {
		require.NotContains(t, seen, k, "duplicate key: %s", k)
		seen[k] = struct{}{}
	}

	// Identical configs must produce the same key (idempotency).
	require.Equal(t, extAuthzFilterKey(base), extAuthzFilterKey(&model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP}))
	// Header order must not affect the key.
	headersAB := &model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP, AllowedRequestHeaders: []string{"A", "B"}}
	headersBA := &model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP, AllowedRequestHeaders: []string{"B", "A"}}
	require.Equal(t, extAuthzFilterKey(headersAB), extAuthzFilterKey(headersBA))
	// Established names remain stable for ordinary configurations.
	require.Equal(t, "HTTP:ns:authz:9000:pp:/check", extAuthzFilterKey(withPrefix))
	// Existing filter names must also remain stable when values contain key delimiters.
	withDelimiters := &model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP, PathPrefix: "/check:tenant,%"}
	require.Equal(t, "HTTP:ns:authz:9000:pp:/check:tenant,%", extAuthzFilterKey(withDelimiters))

	// Selector IDs remain distinct even when the established filter-name serialization collides.
	pathContainingBodyTag := &model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP, PathPrefix: "/check:fb:1"}
	pathAndBody := &model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP, PathPrefix: "/check", ForwardBody: &model.ForwardBodyConfig{MaxSize: 1}}
	require.Equal(t, extAuthzFilterKey(pathContainingBodyTag), extAuthzFilterKey(pathAndBody))
	require.NotEqual(t, extAuthzFilterID(pathContainingBodyTag), extAuthzFilterID(pathAndBody))

	m := &model.Model{HTTP: []model.HTTPListener{{Routes: []model.HTTPRoute{
		{ExternalAuth: pathContainingBodyTag},
		{ExternalAuth: pathAndBody},
	}}}}
	filters := (&cecTranslator{}).getUniqueAuthFilters(m)
	require.Len(t, filters, 2)
	names := extAuthzFilterNames(filters)
	firstName := names[extAuthzFilterID(pathContainingBodyTag)]
	secondName := names[extAuthzFilterID(pathAndBody)]
	require.NotEqual(t, firstName, secondName)

	var emittedNames []string
	for _, filter := range (&cecTranslator{}).getHTTPConnectionManagerHttpFilters(m) {
		if isExternalAuthFilterName(filter.GetName()) {
			emittedNames = append(emittedNames, filter.GetName())
		}
	}
	require.ElementsMatch(t, []string{firstName, secondName}, emittedNames)
	routeConfig := getTypedPerFilterConfig(pathContainingBodyTag, filters, nil, nil, model.HTTPRoute{}, false)
	require.Contains(t, routeConfig, firstName)
	require.Contains(t, routeConfig, secondName)
}

func testExtAuthzFilterID(af *model.HTTPExternalAuthFilter) string {
	return extAuthzFilterID(af)
}

func extAuthzMetadataMatcherValues(config *extauthzv3.ExtAuthz) []string {
	valueMatchers := config.GetFilterEnabledMetadata().GetValue().GetOrMatch().GetValueMatchers()
	values := make([]string, 0, len(valueMatchers))
	for _, matcher := range valueMatchers {
		values = append(values, matcher.GetStringMatch().GetExact())
	}
	return values
}

func Test_desiredHTTPConnectionManagerWithoutGRPCWebTranslation(t *testing.T) {
	i := &cecTranslator{}
	m := &model.Model{
		HTTPOptions: &model.HTTPOptions{
			GRPCWebTranslation: &model.GRPCWebTranslationConfig{
				Enabled: false,
			},
		},
	}
	res, err := i.desiredHTTPConnectionManager("dummy-name", "dummy-route-name", m)
	require.NoError(t, err)

	httpConnectionManager := &httpConnectionManagerv3.HttpConnectionManager{}
	err = proto.Unmarshal(res.Value, httpConnectionManager)
	require.NoError(t, err)

	require.Len(t, httpConnectionManager.GetHttpFilters(), 2)
	require.Equal(t, "envoy.filters.http.grpc_stats", httpConnectionManager.GetHttpFilters()[0].Name)
	require.Equal(t, "envoy.filters.http.router", httpConnectionManager.GetHttpFilters()[1].Name)
}

func Test_desiredHTTPConnectionManager_withExtProc(t *testing.T) {
	i := &cecTranslator{}
	m := &model.Model{
		HTTP: []model.HTTPListener{{
			Routes: []model.HTTPRoute{{
				Backends: []model.Backend{{
					Name:      "llm-pool-shadow-service",
					Namespace: "default",
					Port:      &model.BackendPort{Port: 8000},
					EndpointPicker: &model.EndpointPicker{
						Name: "llm-pool-epp", Namespace: "default", Port: 9002, FailureMode: "FailOpen",
					},
				}},
			}},
		}},
	}

	res, err := i.desiredHTTPConnectionManager("dummy-name", "dummy-route-name", m)
	require.NoError(t, err)

	hcm := &httpConnectionManagerv3.HttpConnectionManager{}
	require.NoError(t, proto.Unmarshal(res.Value, hcm))
	picker := m.HTTP[0].Routes[0].Backends[0].EndpointPicker
	eppCluster := getEPPClusterName(picker)
	filterName := ExtProcFilterName(eppCluster)

	// Locate the ext_proc filter and the router, and confirm ordering.
	idx := map[string]int{}
	for n, f := range hcm.GetHttpFilters() {
		idx[f.Name] = n
	}
	eppIdx, ok := idx[filterName]
	require.True(t, ok, "ext_proc filter %q must be present in the chain", filterName)
	require.True(t, hcm.GetHttpFilters()[eppIdx].GetDisabled(), "ext_proc must require an explicit route enable")
	routerIdx, ok := idx["envoy.filters.http.router"]
	require.True(t, ok)
	require.Less(t, eppIdx, routerIdx, "ext_proc must run before the router")

	// Verify the filter config points at the EPP cluster and honours FailureMode.
	cfg := &extprocv3.ExternalProcessor{}
	require.NoError(t, proto.Unmarshal(hcm.GetHttpFilters()[eppIdx].GetTypedConfig().Value, cfg))
	require.Equal(t, eppCluster, cfg.GetGrpcService().GetEnvoyGrpc().GetClusterName())
	require.True(t, cfg.GetFailureModeAllow(), "FailOpen must map to failure_mode_allow=true")
	require.Equal(t, extprocv3.ProcessingMode_SEND, cfg.GetProcessingMode().GetRequestHeaderMode())
}
