package systemtests

import (
	"io/ioutil"
	"net/http"

	"github.com/contiv/auth_proxy/proxy"

	. "gopkg.in/check.v1"
)

var (
	// endpoint suffixes of netmaster APIs
	epSuffixes = map[string]string{
		"appProfiles":        apName,
		"endpointGroups":     epgName,
		"extContractsGroups": ecgName,
		"netprofiles":        npName,
		"networks":           networkName,
		"policys":            policyName,
		"rules":              ruleName,
		"serviceLBs":         slbName,
	}

	// endpoint suffixes of admin only netmaster APIs
	adminEpSuffixes = map[string]string{
		"globals": "g1",
		"aciGws":  "aciGw1",
		"Bgps":    "bgp1",
	}

	ldapGroupDN = "CN=Domain Admins,CN=Users,DC=contiv,DC=ad,DC=local"
)

// TestRBACFilters tests all the netmaster filter(list) endpoints
func (s *systemtestSuite) TestRBACFilters(c *C) {
	s.addUser(c, username)

	// test all list endpoints
	runTest(func(ms *MockServer) {

		copy := []string{"tenants"}
		for resource := range epSuffixes {
			copy = append(copy, resource)
		}

		for _, resource := range copy {
			endpoint := "/api/v1/" + resource + "/"
			tenantList := `[{"tenantName":"t1"},{"tenantName":"t2"},{"tenantName":"t3"}]`
			ms.AddHardcodedResponse(endpoint, []byte(tenantList))

			// test using `admin` token
			resp, body := proxyGet(c, adToken, endpoint)
			c.Assert(resp.StatusCode, Equals, 200)
			c.Assert(string(body), DeepEquals, tenantList)

			// test using local user
			s.testRBACFiltersHelper(c, loginAs(c, username, username), username, resource, true)

			// test using ldap user
			s.addLdapConfiguration(c, adToken, s.getRunningLdapConfig(true))
			s.testRBACFiltersHelper(c, loginAs(c, ldapTestUsername, ldapPassword), ldapGroupDN, resource, false)
			s.deleteLdapConfiguration(c, adToken)
		}

	})

	// test adminOnly list endpoints
	runTest(func(ms *MockServer) {

		s.addLdapConfiguration(c, adToken, s.getRunningLdapConfig(true))

		for resource := range adminEpSuffixes {
			endpoint := "/api/v1/" + resource + "/"
			respData := `{"foo":"bar"}`
			ms.AddHardcodedResponse(endpoint, []byte(respData))

			// test using `admin` token
			resp, body := proxyGet(c, adToken, endpoint)
			c.Assert(resp.StatusCode, Equals, 200)
			c.Assert(string(body), DeepEquals, string(respData))

			// test using local user
			s.testAdminOnlyHelper(c, loginAs(c, username, username), username, endpoint, respData, true)

			// test using ldap user
			s.testAdminOnlyHelper(c, loginAs(c, ldapTestUsername, ldapPassword), ldapGroupDN, endpoint, respData, false)
		}

		s.deleteLdapConfiguration(c, adToken)

	})
}

// TestRBACOnDELETERequest tests netmaster DELETE endpoints
func (s *systemtestSuite) TestRBACOnDELETERequest(c *C) {
	s.addUser(c, username)

	// test `tenant` delete
	runTest(func(ms *MockServer) {

		endpoint := "/api/v1/tenants/" + tenantName + "/"
		respData := `{"foo":"bar"}`
		ms.AddHardcodedResponse(endpoint, []byte(respData))

		resp, body := proxyDelete(c, adToken, endpoint)
		c.Assert(resp.StatusCode, Equals, 200)
		c.Assert(string(body), DeepEquals, respData)

		// test using local user
		s.testRBACHelper(c, loginAs(c, username, username), username, endpoint, respData, "DELETE", true)

		// test using ldap user
		s.addLdapConfiguration(c, adToken, s.getRunningLdapConfig(true))
		s.testRBACHelper(c, loginAs(c, ldapTestUsername, ldapPassword), ldapGroupDN, endpoint, respData, "DELETE", false)
		s.deleteLdapConfiguration(c, adToken)

	})

	// test all other endpoints
	runTest(func(ms *MockServer) {

		s.addLdapConfiguration(c, adToken, s.getRunningLdapConfig(true))

		for resource, rName := range epSuffixes {
			endpoint := "/api/v1/" + resource + "/" + rName + "/"
			respData := `{"tenantName":"` + tenantName + `"}`
			ms.AddHardcodedResponse(endpoint, []byte(respData))

			// test using `admin` token
			resp, _ := proxyDelete(c, adToken, endpoint)
			c.Assert(resp.StatusCode, Equals, 200)

			// test using local user
			s.testRBACWithinTenantHelper(c, loginAs(c, username, username), username, endpoint, respData, "DELETE", true)

			// test using ldap user
			s.testRBACWithinTenantHelper(c, loginAs(c, ldapTestUsername, ldapPassword), ldapGroupDN, endpoint, respData, "DELETE", false)
		}

		s.deleteLdapConfiguration(c, adToken)

	})

	// test adminOnly list endpoints
	runTest(func(ms *MockServer) {

		s.addLdapConfiguration(c, adToken, s.getRunningLdapConfig(true))

		for resource, rName := range adminEpSuffixes {
			endpoint := "/api/v1/" + resource + "/" + rName + "/"
			respData := `{"foo":"bar"}`
			ms.AddHardcodedResponse(endpoint, []byte(respData))

			// test using `admin` token
			resp, body := proxyDelete(c, adToken, endpoint)
			c.Assert(resp.StatusCode, Equals, 200)
			c.Assert(string(body), DeepEquals, string(respData))

			// test using local user
			s.testAdminOnlyHelper(c, loginAs(c, username, username), username, endpoint, respData, true)

			// test using ldap user
			s.testAdminOnlyHelper(c, loginAs(c, ldapTestUsername, ldapPassword), ldapGroupDN, endpoint, respData, false)
		}

		s.deleteLdapConfiguration(c, adToken)

	})

}

// TestRBACOnGETRequest tests netmaster GET endpoints
func (s *systemtestSuite) TestRBACOnGETRequest(c *C) {
	s.addUser(c, username)

	// test `tenant` get
	runTest(func(ms *MockServer) {

		endpoint := "/api/v1/tenants/" + tenantName + "/"
		respData := `{"foo":"bar"}`
		ms.AddHardcodedResponse(endpoint, []byte(respData))

		// test using `admin` token
		resp, body := proxyGet(c, adToken, endpoint)
		c.Assert(resp.StatusCode, Equals, 200)
		c.Assert(string(body), DeepEquals, respData)

		// test using local user
		s.testRBACHelper(c, loginAs(c, username, username), username, endpoint, respData, "GET", true)

		// test using ldap user
		s.addLdapConfiguration(c, adToken, s.getRunningLdapConfig(true))
		s.testRBACHelper(c, loginAs(c, ldapTestUsername, ldapPassword), ldapGroupDN, endpoint, respData, "GET", false)

		// GET on unauthorized tenant
		endpoint = "/api/v1/tenants/test/"
		resp, body = proxyGet(c, loginAs(c, username, username), endpoint)
		s.assertInsufficientPrivileges(c, resp, body)

		resp, body = proxyGet(c, loginAs(c, ldapTestUsername, ldapPassword), endpoint)
		s.assertInsufficientPrivileges(c, resp, body)

		s.deleteLdapConfiguration(c, adToken)

	})

	// test all other netmaster endpoints
	runTest(func(ms *MockServer) {

		s.addLdapConfiguration(c, adToken, s.getRunningLdapConfig(true))

		for resource, rName := range epSuffixes {
			endpoint := "/api/v1/" + resource + "/" + rName + "/"
			respData := `{"tenantName": "` + tenantName + `"}`
			ms.AddHardcodedResponse(endpoint, []byte(respData))

			// test using `admin` token
			resp, _ := proxyGet(c, adToken, endpoint)
			c.Assert(resp.StatusCode, Equals, 200)

			// test using local user
			s.testRBACWithinTenantHelper(c, loginAs(c, username, username), username, endpoint, respData, "GET", true)

			// test using ldap user
			s.testRBACWithinTenantHelper(c, loginAs(c, ldapTestUsername, ldapPassword), ldapGroupDN, endpoint, respData, "GET", false)
		}

		s.deleteLdapConfiguration(c, adToken)

	})

	// test adminOnly list endpoints
	runTest(func(ms *MockServer) {

		s.addLdapConfiguration(c, adToken, s.getRunningLdapConfig(true))

		for resource, rName := range adminEpSuffixes {
			endpoint := "/api/v1/" + resource + "/" + rName + "/"
			respData := `{"foo":"bar"}`
			ms.AddHardcodedResponse(endpoint, []byte(respData))

			// test using `admin` token
			resp, body := proxyGet(c, adToken, endpoint)
			c.Assert(resp.StatusCode, Equals, 200)
			c.Assert(string(body), DeepEquals, string(respData))

			// test using local user
			s.testAdminOnlyHelper(c, loginAs(c, username, username), username, endpoint, respData, true)

			// test using ldap user
			s.testAdminOnlyHelper(c, loginAs(c, ldapTestUsername, ldapPassword), ldapGroupDN, endpoint, respData, false)
		}

		s.deleteLdapConfiguration(c, adToken)

	})
}

// TestRBACOnPOSTRequest tests netmaster POST endpoints
func (s *systemtestSuite) TestRBACOnPOSTRequest(c *C) {
	s.addUser(c, username)

	// test `tenant` creation
	runTest(func(ms *MockServer) {

		endpoint := "/api/v1/tenants/" + tenantName + "/"
		tenantCreateReq := `{"tenantName": "` + tenantName + `"}`

		// this handler sends the request body back as the response body
		ms.AddHandler(endpoint, func(w http.ResponseWriter, req *http.Request) {
			body, err := ioutil.ReadAll(req.Body)
			c.Assert(err, IsNil)

			w.WriteHeader(http.StatusOK)
			w.Write(body)
		})

		// POST using `admin` token
		resp, body := proxyPost(c, adToken, endpoint, []byte(tenantCreateReq))
		c.Assert(resp.StatusCode, Equals, 200)
		c.Assert(string(body), Equals, tenantCreateReq)

		// test using local user
		s.testRBACHelper(c, loginAs(c, username, username), username, endpoint, tenantCreateReq, "POST", true)

		// test using ldap user
		s.addLdapConfiguration(c, adToken, s.getRunningLdapConfig(true))
		s.testRBACHelper(c, loginAs(c, ldapTestUsername, ldapPassword), ldapGroupDN, endpoint, tenantCreateReq, "POST", false)
		s.deleteLdapConfiguration(c, adToken)

	})

	// test all other netmaster endpoints
	runTest(func(ms *MockServer) {

		s.addLdapConfiguration(c, adToken, s.getRunningLdapConfig(true))

		for resource, rName := range epSuffixes {
			endpoint := "/api/v1/" + resource + "/" + rName + "/"
			createReq := `{"tenantName": "` + tenantName + `"}`

			// this handler sends the request body back as the response body
			ms.AddHandler(endpoint, func(w http.ResponseWriter, req *http.Request) {
				body, err := ioutil.ReadAll(req.Body)
				c.Assert(err, IsNil)

				w.WriteHeader(http.StatusOK)
				w.Write(body)
			})

			// POST using `admin` token
			resp, body := proxyPost(c, adToken, endpoint, []byte(createReq))
			c.Assert(resp.StatusCode, Equals, 200)
			c.Assert(string(body), Equals, createReq)

			// test using local user
			s.testRBACWithinTenantHelper(c, loginAs(c, username, username), username, endpoint, createReq, "POST", true)

			// test using ldap user
			s.testRBACWithinTenantHelper(c, loginAs(c, ldapTestUsername, ldapPassword), ldapGroupDN, endpoint, createReq, "POST", false)
		}

		s.deleteLdapConfiguration(c, adToken)

	})

	// test adminOnly list endpoints
	runTest(func(ms *MockServer) {

		s.addLdapConfiguration(c, adToken, s.getRunningLdapConfig(true))

		for resource, rName := range adminEpSuffixes {
			endpoint := "/api/v1/" + resource + "/" + rName + "/"
			respData := `{"foo":"bar"}`
			ms.AddHardcodedResponse(endpoint, []byte(respData))

			// test using `admin` token
			resp, body := proxyPost(c, adToken, endpoint, []byte(respData))
			c.Assert(resp.StatusCode, Equals, 200)
			c.Assert(string(body), DeepEquals, string(respData))

			// test using local user
			s.testAdminOnlyHelper(c, loginAs(c, username, username), username, endpoint, respData, true)

			// test using ldap user
			s.testAdminOnlyHelper(c, loginAs(c, ldapTestUsername, ldapPassword), ldapGroupDN, endpoint, respData, false)
		}

		s.deleteLdapConfiguration(c, adToken)

	})

}

// test /globals/global endpoint
func (s *systemtestSuite) TestRBACOnGlobalEndpoint(c *C) {
	testUsr := "test_global"
	s.addUser(c, testUsr)

	runTest(func(ms *MockServer) {
		userToken := loginAs(c, testUsr, testUsr)

		// test /inspect/globals/global/
		endpoint := "/api/v1/inspect/globals/global/"
		respData := `{"foo":"bar"}`
		ms.AddHardcodedResponse(endpoint, []byte(respData))

		// test using admin token
		resp, body := proxyGet(c, adToken, endpoint)
		c.Assert(resp.StatusCode, Equals, 200)
		c.Assert(string(body), DeepEquals, string(respData))

		// test using local `testUsr` token
		resp, body = proxyGet(c, userToken, endpoint)
		c.Assert(resp.StatusCode, Equals, 200)
		c.Assert(string(body), DeepEquals, string(respData))

		// test using ldap user
		s.addLdapConfiguration(c, adToken, s.getRunningLdapConfig(true))
		resp, body = proxyGet(c, loginAs(c, ldapTestUsername, ldapPassword), endpoint)
		c.Assert(resp.StatusCode, Equals, 200)
		c.Assert(string(body), DeepEquals, string(respData))
		s.deleteLdapConfiguration(c, adToken)

	})
}

// helper function to test RBAC filters
func (s *systemtestSuite) testRBACFiltersHelper(c *C, userToken, principalName, resource string, isLocal bool) {
	endpoint := "/api/v1/" + resource + "/"

	// test using user token
	resp, body := proxyGet(c, userToken, endpoint)
	c.Assert(resp.StatusCode, Equals, 200)
	c.Assert(string(body), Equals, "[]")

	var authzRequest string
	if isLocal {
		authzRequest = `{"PrincipalName":"` + principalName + `","local":true,"role":"ops","tenantName":"t1"}`
	} else {
		authzRequest = `{"PrincipalName":"` + principalName + `","local":false,"role":"ops","tenantName":"t1"}`
	}

	// grant tenant `t1` access to `principalName`
	authz1 := s.addAuthorization(c, authzRequest, adToken)

	// test again using user token
	resp, body = proxyGet(c, userToken, endpoint)
	c.Assert(resp.StatusCode, Equals, 200)
	s.processListResponse(c, resource, string(body), []string{"t1"})

	if isLocal {
		authzRequest = `{"PrincipalName":"` + principalName + `","local":true,"role":"ops","tenantName":"t3"}`
	} else {
		authzRequest = `{"PrincipalName":"` + principalName + `","local":false,"role":"ops","tenantName":"t3"}`
	}

	// grant tenant `t3` access to `principalName`
	authz2 := s.addAuthorization(c, authzRequest, adToken)

	// test again using user token; new tenant `t3` should also be listed
	resp, body = proxyGet(c, userToken, endpoint)
	c.Assert(resp.StatusCode, Equals, 200)
	s.processListResponse(c, resource, string(body), []string{"t1", "t3"})

	s.deleteAuthorization(c, authz1.AuthzUUID, adToken)
	s.deleteAuthorization(c, authz2.AuthzUUID, adToken)

	// test using user token; all authzs removed
	resp, body = proxyGet(c, userToken, endpoint)
	c.Assert(resp.StatusCode, Equals, 200)
	c.Assert(string(body), Equals, "[]")
}

// TestAdminRoleRequired tests that a user can only perform an admin level API
// call when it has an admin authorization for it. The way this test is
// different from other rbac tests is that it tests granting admin access to a
// user.
func (s *systemtestSuite) TestAdminRoleRequired(c *C) {
	// This also sets up the adToken variable
	s.addUser(c, username)

	runTest(func(ms *MockServer) {

		// login as username, should succeed
		testuserToken := loginAs(c, username, username)

		// update user details using his/her token
		data := `{"first_name":"Temp", "last_name": "User"}`
		endpoint := proxy.V1Prefix + "/local_users/" + username
		resp, _ := proxyPatch(c, testuserToken, endpoint+"/", []byte(data))
		c.Assert(resp.StatusCode, Equals, 200)

		// try updating other user details
		endpoint = proxy.V1Prefix + "/local_users/unknown"
		resp, _ = proxyPatch(c, testuserToken, endpoint+"/", []byte(data))
		// user is not allowed to update other user details
		c.Assert(resp.StatusCode, Equals, 403)

		// grant admin access to username
		data = `{"PrincipalName":"` + username + `","local":true,"role":"admin","tenantName":""}`
		authz := s.addAuthorization(c, data, adToken)

		// retry calling the update api, it should succeed even now
		data = `{"first_name":"Temp", "last_name": "User"}`
		respBody := `{"username":"` + username + `","first_name":"Temp","last_name":"User","disable":false}`
		s.updateLocalUser(c, username, data, respBody, testuserToken)

		// delete authorization
		s.deleteAuthorization(c, authz.AuthzUUID, adToken)

		// update using user's token
		endpoint = proxy.V1Prefix + "/local_users/" + username
		resp, _ = proxyPatch(c, testuserToken, endpoint+"/", []byte(data))
		c.Assert(resp.StatusCode, Equals, 200)

		// Below tests the adminOnly api
		s.testAdminOnlyAPI(c)
	})
}
