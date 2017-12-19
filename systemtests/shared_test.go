package systemtests

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/contiv/auth_proxy/common/types"
	"github.com/contiv/auth_proxy/proxy"
	. "gopkg.in/check.v1"
)

const (
	// XXX: Yuva's dev server
	ldapServer        = "10.193.231.158"
	ldapPassword      = "C1ntainer$"
	ldapAdminPassword = "C1ntainer$!"
	ldapTestUsername  = "test_user"
	tlsCertIssuedTo   = "WIN-EDME78NSVJO.contiv.ad.local"

	// use this when testing unauthenticated endpoints instead of ""
	noToken = ""
)

var (
	adToken  = ""
	username = "test_rbac"

	tenantName  = "t1"
	networkName = "n1"
	epgName     = "epg1"
	apName      = "ap1"
	ecgName     = "ecg1"
	npName      = "np1"
	policyName  = "p1"
	ruleName    = "r1"
	slbName     = "slb1"

	endpoint = proxy.V1Prefix + "/ldap_configuration" + "/"

	builtInUsers     = []string{types.Admin.String(), types.Ops.String()}
	newUsers         = []string{"xxx", "yyy-4", "zzz_@"}
	invalidUsernames = []string{"test$!", "%6ADF7*)(", "docstest6^$)_$#", "~123$sdsdf"}
)

func (s *systemtestSuite) getRunningLdapConfig(startTLS bool) string {
	ldapConfig := `"server":"` + ldapServer + `",` +
		`"port":5678,` +
		`"base_dn":"DC=contiv,DC=ad,DC=local",` +
		`"service_account_dn":"CN=Service Account,CN=Users,DC=contiv,DC=ad,DC=local",` +
		`"service_account_password":"` + ldapPassword + `"`

	if startTLS {
		return `{` + ldapConfig + `,` +
			`"start_tls":true,` +
			`"insecure_skip_verify":false,` +
			`"tls_cert_issued_to":"` + tlsCertIssuedTo + `"}`
	}

	return `{` + ldapConfig + `,` +
		`"start_tls":false,` +
		`"insecure_skip_verify":false,` +
		`"tls_cert_issued_to":""}`
}

// addAuthorization helper function for the tests
func (s *systemtestSuite) addAuthorization(c *C, data, token string) proxy.GetAuthorizationReply {
	endpoint := proxy.V1Prefix + "/authorizations"

	resp, body := proxyPost(c, token, endpoint+"/", []byte(data))
	c.Assert(resp.StatusCode, Equals, 201)

	authz := proxy.GetAuthorizationReply{}
	c.Assert(json.Unmarshal(body, &authz), IsNil)
	return authz
}

// getAuthorization helper function for the tests
func (s *systemtestSuite) getAuthorization(c *C, authzUUID, token string) proxy.GetAuthorizationReply {
	endpoint := proxy.V1Prefix + "/authorizations/" + authzUUID + "/"

	resp, body := proxyGet(c, token, endpoint)
	c.Assert(resp.StatusCode, Equals, 200)

	authz := proxy.GetAuthorizationReply{}
	c.Assert(json.Unmarshal(body, &authz), IsNil)
	return authz
}

// getAuthorizations helper function for the tests
func (s *systemtestSuite) getAuthorizations(c *C, token string) []proxy.GetAuthorizationReply {
	endpoint := proxy.V1Prefix + "/authorizations" + "/"

	resp, body := proxyGet(c, token, endpoint)
	c.Assert(resp.StatusCode, Equals, 200)

	authzs := []proxy.GetAuthorizationReply{}
	c.Assert(json.Unmarshal(body, &authzs), IsNil)
	return authzs
}

// deleteAuthorization helper function for the tests
func (s *systemtestSuite) deleteAuthorization(c *C, authzUUID, token string) {
	endpoint := proxy.V1Prefix + "/authorizations/" + authzUUID + "/"

	resp, _ := proxyDelete(c, token, endpoint)
	c.Assert(resp.StatusCode, Equals, 204)
}

// addLdapConfiguration helper function for the tests
func (s *systemtestSuite) addLdapConfiguration(c *C, token, data string) {
	resp, _ := proxyPut(c, token, endpoint, []byte(data))
	c.Assert(resp.StatusCode, Equals, 200)
}

// deleteLdapConfiguration helper function for the tests
func (s *systemtestSuite) deleteLdapConfiguration(c *C, token string) {
	resp, body := proxyDelete(c, token, endpoint)
	c.Assert(resp.StatusCode, Equals, 204)
	c.Assert(body, DeepEquals, []byte{})
}

// getLdapConfiguration helper function for the tests
func (s *systemtestSuite) getLdapConfiguration(c *C, token string) []byte {
	resp, body := proxyGet(c, token, endpoint)
	c.Assert(resp.StatusCode, Equals, 200)

	return body
}

// updateLdapConfiguration helper function for the tests
func (s *systemtestSuite) updateLdapConfiguration(c *C, token, data string) {
	resp, _ := proxyPatch(c, token, endpoint, []byte(data))
	c.Assert(resp.StatusCode, Equals, 200)
}

// userUpdateEndpoint tests update on local user
func (s *systemtestSuite) userUpdate(c *C) {

	runTest(func(ms *MockServer) {
		token := adminToken(c)

		for _, username := range newUsers {
			// add new local_user to the system
			data := `{"username":"` + username + `","password":"` + username + `", "disable":false}`
			respBody := `{"username":"` + username + `","first_name":"","last_name":"","disable":false}`
			s.addLocalUser(c, data, respBody, token)

			// try login using `username`
			_ = loginAs(c, username, username)

			// update `testuser` details
			data = `{"first_name":"Temp", "last_name": "User"}`
			respBody = `{"username":"` + username + `","first_name":"Temp","last_name":"User","disable":false}`
			s.updateLocalUser(c, username, data, respBody, token)

			// try login again using `username` after update
			_ = loginAs(c, username, username)

			// update `username`'s password
			data = `{"password":"test"}`
			s.updateLocalUser(c, username, data, respBody, token)

			// try login again using old password
			testuserToken, resp, err := login(username, username)
			c.Assert(err, IsNil)
			c.Assert(resp.StatusCode, Equals, 401)
			c.Assert(len(testuserToken), Equals, 0)

			// try login again using new password
			_ = loginAs(c, username, "test")

			// test updating the user details using the user's token
			userToken := loginAs(c, username, "test")
			data = `{"first_name":"Test", "last_name": "User"}`
			respBody = `{"username":"` + username + `","first_name":"Test","last_name":"User","disable":false}`
			s.updateLocalUser(c, username, data, respBody, userToken)

			// update `username`'s password using his/her token
			data = `{"password":"test!"}`
			s.updateLocalUser(c, username, data, respBody, userToken)
		}
	})
}

// builtInUserUpdate tests built-in user update functionality
func (s *systemtestSuite) builtInUserUpdate(c *C) {

	runTest(func(ms *MockServer) {
		token := adminToken(c)

		for _, username := range builtInUsers {
			// update user details
			data := `{"first_name":"Built-in", "last_name": "User", "disable":false}`
			respBody := `{"username":"` + username + `","first_name":"Built-in","last_name":"User","disable":false}`
			s.updateLocalUser(c, username, data, respBody, token)

			// login
			testuserToken := loginAs(c, username, username)
			c.Assert(len(testuserToken), Not(Equals), 0)

			// update password
			data = `{"password":"test"}`
			s.updateLocalUser(c, username, data, respBody, token)

			// try login again using old password
			testuserToken, resp, err := login(username, username)
			c.Assert(err, IsNil)
			c.Assert(resp.StatusCode, Equals, 401)
			c.Assert(len(testuserToken), Equals, 0)

			// try login again using new password
			testuserToken = loginAs(c, username, "test")
			c.Assert(len(testuserToken), Not(Equals), 0)

			// revert password so that it wont block other tests
			data = `{"password":"` + username + `"}`
			s.updateLocalUser(c, username, data, respBody, token)
		}
	})
}

// addLocalUser helper function for the tests
func (s *systemtestSuite) addLocalUser(c *C, data, expectedRespBody, token string) {
	endpoint := proxy.V1Prefix + "/local_users"

	resp, body := proxyPost(c, token, endpoint+"/", []byte(data))
	c.Assert(resp.StatusCode, Equals, 201)
	c.Assert(string(body), DeepEquals, expectedRespBody)
}

// updateLocalUser helper function for the tests
func (s *systemtestSuite) updateLocalUser(c *C, username, data, expectedRespBody, token string) {
	endpoint := proxy.V1Prefix + "/local_users/" + username

	resp, body := proxyPatch(c, token, endpoint+"/", []byte(data))
	c.Assert(resp.StatusCode, Equals, 200)
	c.Assert(string(body), DeepEquals, expectedRespBody)
}

// helper function to test adminOnly endpoints
func (s *systemtestSuite) testAdminOnlyHelper(c *C, userToken, principalName, endpoint, respData string, isLocal bool) {
	// test using user token
	resp, body := proxyGet(c, userToken, endpoint)
	s.assertInsufficientPrivileges(c, resp, body)

	var ldapConfig string
	if isLocal {
		ldapConfig = `{"PrincipalName":"` + principalName + `","local":true,"role":"` + types.Admin.String() + `"}`
	} else {
		ldapConfig = `{"PrincipalName":"` + principalName + `","local":false,"role":"` + types.Admin.String() + `"}`
	}

	// add admin authz for `principalName`
	authz := s.addAuthorization(c, ldapConfig, adToken)

	// test again using user token
	resp, body = proxyGet(c, userToken, endpoint)
	c.Assert(resp.StatusCode, Equals, 200)
	c.Assert(string(body), DeepEquals, respData)

	s.deleteAuthorization(c, authz.AuthzUUID, userToken)
}

// helper function to test RBAC within the tenant (network, epg, etc.)
func (s *systemtestSuite) testRBACWithinTenantHelper(c *C, userToken, principalName, endpoint, data, method string, isLocal bool) {
	var resp *http.Response
	var body []byte

	// test using user token
	switch method {
	case "GET":
		resp, body = proxyGet(c, userToken, endpoint)
	case "DELETE":
		resp, body = proxyDelete(c, userToken, endpoint)
	case "POST":
		resp, body = proxyPost(c, userToken, endpoint, []byte(data))
	}

	// user does not have access to the tenant `tenantName`
	s.assertInsufficientPrivileges(c, resp, body)

	var authzRequest string
	if isLocal {
		authzRequest = `{"PrincipalName":"` + principalName + `","local":true,"role":"ops","tenantName":"` + tenantName + `"}`
	} else {
		authzRequest = `{"PrincipalName":"` + principalName + `","local":false,"role":"ops","tenantName":"` + tenantName + `"}`
	}

	// add tenant authorization
	authz := s.addAuthorization(c, authzRequest, adToken)

	// test after adding tenant authorization
	// user can create/delete/get on any object within the authorized tenant
	switch method {
	case "GET":
		resp, body = proxyGet(c, userToken, endpoint)
		c.Assert(resp.StatusCode, Equals, 200)
		c.Assert(string(body), DeepEquals, data)
	case "DELETE":
		resp, body = proxyDelete(c, userToken, endpoint)
		c.Assert(resp.StatusCode, Equals, 200)
		c.Assert(string(body), Equals, data)
	case "POST":
		resp, body = proxyPost(c, userToken, endpoint, []byte(data))
		c.Assert(resp.StatusCode, Equals, 200)
		c.Assert(string(body), DeepEquals, data)
	}

	s.deleteAuthorization(c, authz.AuthzUUID, adToken)
}

// helper function to test tenant operations (create/delete/get)
func (s *systemtestSuite) testRBACHelper(c *C, userToken, principalName, endpoint, data, method string, isLocal bool) {
	var resp *http.Response
	var body []byte

	// test using user token
	switch method {
	case "GET":
		resp, body = proxyGet(c, userToken, endpoint)
	case "DELETE":
		resp, body = proxyDelete(c, userToken, endpoint)
	case "POST":
		resp, body = proxyPost(c, userToken, endpoint, []byte(data))
	}

	// user does not have access to the tenant `tenantName`
	s.assertInsufficientPrivileges(c, resp, body)

	var authzRequest string
	if isLocal {
		authzRequest = `{"PrincipalName":"` + principalName + `","local":true,"role":"ops","tenantName":"` + tenantName + `"}`
	} else {
		authzRequest = `{"PrincipalName":"` + principalName + `","local":false,"role":"ops","tenantName":"` + tenantName + `"}`
	}

	// add tenant authorization
	authz := s.addAuthorization(c, authzRequest, adToken)

	// test after adding tenant authorization
	// Only admin can create/delete tenants; but the authorized user can view (GET) the tenant
	switch method {
	case "GET":
		resp, body = proxyGet(c, userToken, endpoint)
		c.Assert(resp.StatusCode, Equals, 200)
		c.Assert(string(body), DeepEquals, data)
	case "DELETE":
		resp, body = proxyDelete(c, userToken, endpoint)
		s.assertInsufficientPrivileges(c, resp, body)
	case "POST":
		resp, body = proxyPost(c, userToken, endpoint, []byte(data))
		s.assertInsufficientPrivileges(c, resp, body)
	}

	s.deleteAuthorization(c, authz.AuthzUUID, adToken)
}

// addUser helper function that adds a new local user to the system
func (s *systemtestSuite) addUser(c *C, username string) {
	// add new local user
	runTest(func(ms *MockServer) {
		adToken = adminToken(c)

		endpoint := proxy.V1Prefix + "/local_users/" + username + "/"
		resp, _ := proxyGet(c, adToken, endpoint)
		if resp.StatusCode == 200 {
			resp, body := proxyDelete(c, adToken, endpoint)
			c.Assert(resp.StatusCode, Equals, 204)
			c.Assert(body, DeepEquals, []byte{})
		}

		data := `{"username":"` + username + `","password":"` + username + `", "disable":false}`
		respBody := `{"username":"` + username + `","first_name":"","last_name":"","disable":false}`
		s.addLocalUser(c, data, respBody, adToken)

	})
}

// processListResponse constructs the expected response body with the given
// params and checks it against the actual response body
func (s *systemtestSuite) processListResponse(c *C, resource, body string, expectedTenants []string) {

	expectedResponse := []string{}
	switch resource {
	case "tenants":
		for _, tenantName := range expectedTenants {
			expectedResponse = append(expectedResponse, `{"tenantName":"`+tenantName+`","link-sets":{}}`)
		}
		c.Assert(body, DeepEquals, "["+strings.Join(expectedResponse, ",")+"]")
	case "networks", "policys", "appProfiles", "netprofiles":
		for _, tenantName := range expectedTenants {
			expectedResponse = append(expectedResponse, `{"tenantName":"`+tenantName+`","link-sets":{},"links":{"Tenant":{}}}`)
		}
		c.Assert(body, DeepEquals, "["+strings.Join(expectedResponse, ",")+"]")
	case "endpointGroups":
		for _, tenantName := range expectedTenants {
			expectedResponse = append(expectedResponse, `{"tenantName":"`+tenantName+`","link-sets":{},"links":{"AppProfile":{},"NetProfile":{},"Network":{},"Tenant":{}}}`)
		}
		c.Assert(body, DeepEquals, "["+strings.Join(expectedResponse, ",")+"]")
	case "rules":
		for _, tenantName := range expectedTenants {
			expectedResponse = append(expectedResponse, `{"tenantName":"`+tenantName+`","link-sets":{},"links":{"MatchEndpointGroup":{}}}`)
		}
		c.Assert(body, DeepEquals, "["+strings.Join(expectedResponse, ",")+"]")
	case "serviceLBs":
		for _, tenantName := range expectedTenants {
			expectedResponse = append(expectedResponse, `{"tenantName":"`+tenantName+`","links":{"Network":{},"Tenant":{}}}`)
		}
		c.Assert(body, DeepEquals, "["+strings.Join(expectedResponse, ",")+"]")
	default:
		c.Assert(body, DeepEquals, "[]")
	}

}

// assertInsufficientPrivileges helper function that asserts 403
func (s *systemtestSuite) assertInsufficientPrivileges(c *C, resp *http.Response, body []byte) {
	c.Assert(resp.StatusCode, Equals, 403)
	c.Assert(string(body), DeepEquals, `{"error":"Insufficient privileges"}`)
}

// testAdminOnlyAPI helper function TestAdminRoleRequired
func (s *systemtestSuite) testAdminOnlyAPI(c *C) {
	testuserToken := loginAs(c, username, username)

	// try calling an admin api (e.g., add user) using test user token
	// This should fail with forbidden since user doesn't have admin access
	data := `{"username":"test_xyz", "password":"test", "first_name":"Temp", "last_name": "User"}`
	endpoint := proxy.V1Prefix + "/local_users"
	resp, _ := proxyPost(c, testuserToken, endpoint+"/", []byte(data))
	c.Assert(resp.StatusCode, Equals, 403)

	// grant admin access to username
	data = `{"PrincipalName":"` + username + `","local":true,"role":"admin","tenantName":""}`
	authz := s.addAuthorization(c, data, adToken)

	// retry calling the admin api, it should succeed now
	data = `{"username":"test_xyz", "password":"test", "first_name":"Temp", "last_name": "User"}`
	respBody := `{"username":"test_xyz","first_name":"Temp","last_name":"User","disable":false}`
	s.addLocalUser(c, data, respBody, testuserToken)

	// delete authorization
	s.deleteAuthorization(c, authz.AuthzUUID, adToken)

	// calling admin api should fail again without requiring new token (since cached value
	// of role authz in token isn't used)
	resp, _ = proxyPost(c, testuserToken, endpoint+"/", []byte(data))
	c.Assert(resp.StatusCode, Equals, 403)
}
