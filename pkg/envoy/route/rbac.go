package route

import (
	"fmt"

	xds_rbac "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	xds_http_rbac "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	xds_matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/google/uuid"

	"github.com/openservicemesh/osm/pkg/envoy"
	"github.com/openservicemesh/osm/pkg/identity"
	"github.com/openservicemesh/osm/pkg/service"
)

// buildRBACFilter builds an RBAC filter based on SMI TrafficTarget policies.
// The returned RBAC filter has policies that gives downstream principals full access to the local service.
func buildRBACFilter() (map[string]*any.Any, error) {
	svcAccount := service.K8sServiceAccount{Name: uuid.New().String(), Namespace: "foo"}
	httpRBACPolicy, err := buildInboundRBACPolicies(svcAccount)
	if err != nil {
		log.Error().Err(err).Msgf("Error building inbound RBAC policies for principal %q", svcAccount)
		return nil, err
	}

	marshalledRbacPerRoute, err := envoy.MessageToAny(httpRBACPolicy)
	if err != nil {
		log.Error().Err(err).Msgf("Error marshalling RBAC policy: %v", httpRBACPolicy)
		return nil, err
	}

	rbacFilter := map[string]*any.Any{wellknown.HTTPRoleBasedAccessControl: marshalledRbacPerRoute}
	return rbacFilter, nil
}

// buildInboundRBACPolicies builds the RBAC policies based on allowed principals
func buildInboundRBACPolicies(svcAccount service.K8sServiceAccount) (*xds_http_rbac.RBACPerRoute, error) {
	allowsInboundSvcAccounts := []service.K8sServiceAccount{
		{Name: "bookbuyer", Namespace: "bookbuyer"},
		//{Name: "bookstore-v1", Namespace: "bookstore"},
		//{Name: "bookstore-v2", Namespace: "bookstore"},
		{Name: "foo", Namespace: "bar"},
	}

	log.Trace().Msgf("Building RBAC policies for ServiceAccount %q with allowed inbound %v", svcAccount, allowsInboundSvcAccounts)

	// Each downstream is a principal in the RBAC policy, which will have its own permissions
	// based on SMI TrafficTarget policies.
	rbacPolicies := make(map[string]*xds_rbac.Policy)
	for _, downstreamSvcAccount := range allowsInboundSvcAccounts {
		policyName := getPolicyName(downstreamSvcAccount, svcAccount)
		principal := identity.GetKubernetesServiceIdentity(downstreamSvcAccount, identity.ClusterLocalTrustDomain)
		rbacPolicies[policyName] = buildAllowAllPermissionsPolicy(principal)
	}

	httpRBAC := &xds_http_rbac.RBAC{
		Rules: &xds_rbac.RBAC{
			Action:   xds_rbac.RBAC_ALLOW, // Allows the request if and only if there is a policy that matches the request
			Policies: rbacPolicies,
		},
	}

	httpRBACPerRoute := &xds_http_rbac.RBACPerRoute{
		Rbac: httpRBAC,
	}

	return httpRBACPerRoute, nil
}

// buildAllowAllPermissionsPolicy creates an XDS RBAC policy for the given client principal to be granted all access
func buildAllowAllPermissionsPolicy(clientPrincipal identity.ServiceIdentity) *xds_rbac.Policy {
	return &xds_rbac.Policy{
		Permissions: []*xds_rbac.Permission{
			{
				// Grant the given principal all access
				Rule: &xds_rbac.Permission_Any{Any: true},
			},
		},
		Principals: []*xds_rbac.Principal{
			{
				Identifier: &xds_rbac.Principal_OrIds{
					OrIds: &xds_rbac.Principal_Set{
						Ids: []*xds_rbac.Principal{
							getPrincipalAuthenticated(clientPrincipal.String()),
						},
					},
				},
			},
		},
	}
}

// getPolicyName returns a policy name for the policy used to authorize a downstream service account by the upstream
func getPolicyName(downstream, upstream service.K8sServiceAccount) string {
	return fmt.Sprintf("%s to %s", downstream, upstream)
}

func getPrincipalAuthenticated(principalName string) *xds_rbac.Principal {
	return &xds_rbac.Principal{
		Identifier: &xds_rbac.Principal_Authenticated_{
			Authenticated: &xds_rbac.Principal_Authenticated{
				PrincipalName: &xds_matcher.StringMatcher{
					MatchPattern: &xds_matcher.StringMatcher_Exact{
						Exact: principalName,
					},
				},
			},
		},
	}
}
