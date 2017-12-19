package systemtests

import (
	"net/http"

	"github.com/contiv/auth_proxy/common/types"
	"github.com/contiv/auth_proxy/proxy"
	. "gopkg.in/check.v1"
)

// TestBuiltinLocalUsers tests that builtInUsers are pre-defined in the system
func (s *systemtestSuite) TestBuiltinLocalUsers(c *C) {
	runTest(func(ms *MockServer) {
		for _, username := range builtInUsers {
			loginAs(c, username, username)
		}

	})
}

// TestLocalUserEndpoints tests auth_proxy's local user endpoints
func (s *systemtestSuite) TestLocalUserEndpoints(c *C) {

	runTest(func(ms *MockServer) {
		token := adminToken(c)

		for _, username := range newUsers {
			endpoint := proxy.V1Prefix + "/local_users"
			resp, body := proxyGet(c, token, endpoint+"/")
			c.Assert(resp.StatusCode, Equals, 200)
			c.Assert(len(body), Not(Equals), 0)

			// add new local_user to the system
			data := `{"username":"` + username + `","password":"` + username + `", "disable":false}`
			respBody := `{"username":"` + username + `","first_name":"","last_name":"","disable":false}`
			s.addLocalUser(c, data, respBody, token)

			// get `username`
			endpoint = proxy.V1Prefix + "/local_users/" + username
			resp, body = proxyGet(c, token, endpoint+"/")
			c.Assert(resp.StatusCode, Equals, 200)
			c.Assert(string(body), DeepEquals, respBody)

			// try login using `username`
			testuserToken := loginAs(c, username, username)
			c.Assert(len(testuserToken), Not(Equals), 0)

			// delete `username`
			resp, body = proxyDelete(c, token, endpoint+"/")
			c.Assert(resp.StatusCode, Equals, 204)
			c.Assert(len(body), Equals, 0)

			// get `username`
			resp, body = proxyGet(c, token, endpoint+"/")
			c.Assert(resp.StatusCode, Equals, 404)
			c.Assert(len(body), Equals, 0)
		}

		endpoint := proxy.V1Prefix + "/local_users"

		// test usernames with special characters
		for _, username := range invalidUsernames {
			data := `{"username": "` + username + `", "password":"test"}`
			resp, body := proxyPost(c, token, endpoint+"/", []byte(data))
			c.Assert(resp.StatusCode, Equals, http.StatusBadRequest)
			c.Assert(string(body), Matches, ".*Invalid username.*")
		}
	})
}

// TestLocalUserUpdateEndpoint tests auth_proxy's local user update endpoint
func (s *systemtestSuite) TestLocalUserUpdateEndpoint(c *C) {
	s.userUpdate(c)
	s.builtInUserUpdate(c)
}

// TestInvalidUserTokens tests tokens that are either deleted/disabled
func (s *systemtestSuite) TestInvalidUserTokens(c *C) {

	runTest(func(ms *MockServer) {
		token := adminToken(c)

		for _, username := range newUsers {
			data := `{"username":"` + username + `","password":"` + username + `", "disable":false}`
			respBody := `{"username":"` + username + `","first_name":"","last_name":"","disable":false}`
			s.addLocalUser(c, data, respBody, token)
		}

		// test login using disabled account
		for _, username := range append(newUsers, types.Ops.String()) {
			// try login using `username`
			userToken := loginAs(c, username, username)

			// disable user accounts
			data := `{"disable":true}`
			respBody := `{"username":"` + username + `","first_name":"","last_name":"","disable":true}`
			s.updateLocalUser(c, username, data, respBody, token)

			// try login using the disabled account
			testuserToken, resp, err := login(username, username)
			c.Assert(err, IsNil)
			c.Assert(resp.StatusCode, Equals, http.StatusUnauthorized)
			c.Assert(len(testuserToken), Equals, 0)

			// revert the settings using disabled user token
			data = `{"disable":false}`
			endpoint := proxy.V1Prefix + "/local_users/" + username + "/"
			resp, body := proxyPatch(c, userToken, endpoint, []byte(data))
			c.Assert(resp.StatusCode, Equals, http.StatusUnauthorized)
			c.Assert(string(body), Matches, ".*User account disabled.*")

			// revert back; enable the account
			respBody = `{"username":"` + username + `","first_name":"","last_name":"","disable":false}`
			s.updateLocalUser(c, username, data, respBody, token)
		}

		// test login using deleted user account
		for _, username := range newUsers {
			// try login using `username`
			userToken := loginAs(c, username, username)

			// delete user account
			endpoint := proxy.V1Prefix + "/local_users/" + username + "/"
			resp, body := proxyDelete(c, token, endpoint)
			c.Assert(resp.StatusCode, Equals, http.StatusNoContent)
			c.Assert(len(body), Equals, 0)

			// try login using the deleted account
			testuserToken, resp, err := login(username, username)
			c.Assert(err, IsNil)
			c.Assert(resp.StatusCode, Equals, http.StatusUnauthorized)
			c.Assert(len(testuserToken), Equals, 0)

			// access resources using `userToken` (not valid anymore)
			resp, body = proxyGet(c, userToken, endpoint)
			c.Assert(resp.StatusCode, Equals, http.StatusUnauthorized)
			c.Assert(string(body), Matches, ".*Invalid user.*")
		}

		// test accessing resources using disabled built-in `ops` account
		username := types.Ops.String()
		// try login using `username`
		userToken := loginAs(c, username, username)

		// add admin authz for `username`
		data := `{"PrincipalName":"` + username + `","local":true,"role":"` + types.Admin.String() + `"}`
		_ = s.addAuthorization(c, data, token)

		// access resources
		for _, resource := range []string{"networks", "rules"} {
			endpoint := "/api/v1/" + resource + "/"
			ms.AddHardcodedResponse(endpoint, []byte("test"))
			resp, _ := proxyGet(c, userToken, endpoint)
			c.Assert(resp.StatusCode, Equals, http.StatusOK)
		}

		// disable user accounts
		data = `{"disable":true}`
		respBody := `{"username":"` + username + `","first_name":"","last_name":"","disable":true}`
		s.updateLocalUser(c, username, data, respBody, token)

		// access resources
		for _, resource := range []string{"networks", "rules"} {
			endpoint := "/api/v1/" + resource + "/"
			resp, body := proxyGet(c, userToken, endpoint)
			c.Assert(resp.StatusCode, Equals, http.StatusUnauthorized)
			c.Assert(string(body), Matches, ".*User account disabled.*")
		}
	})
}

// TestLocalUserDeleteEndpoint tests auth_proxy's local user delete endpoint
func (s *systemtestSuite) TestLocalUserDeleteEndpoint(c *C) {

	runTest(func(ms *MockServer) {
		token := adminToken(c)

		// add and delete new users
		for _, username := range newUsers {
			// add new local_user to the system
			data := `{"username":"` + username + `","password":"` + username + `", "disable":false}`
			respBody := `{"username":"` + username + `","first_name":"","last_name":"","disable":false}`
			s.addLocalUser(c, data, respBody, token)

			endpoint := proxy.V1Prefix + "/local_users/" + username

			// delete `username`
			resp, body := proxyDelete(c, token, endpoint+"/")
			c.Assert(resp.StatusCode, Equals, 204)
			c.Assert(len(body), Equals, 0)

			// get `username`
			resp, body = proxyGet(c, token, endpoint+"/")
			c.Assert(resp.StatusCode, Equals, 404)
			c.Assert(len(body), Equals, 0)
		}

		// delete built-in users
		for _, username := range builtInUsers {
			endpoint := proxy.V1Prefix + "/local_users/" + username

			// delete `username`
			resp, body := proxyDelete(c, token, endpoint+"/")
			c.Assert(resp.StatusCode, Equals, 400)
			c.Assert(len(body), Not(Equals), 0)

			// get `username`
			resp, body = proxyGet(c, token, endpoint+"/")
			c.Assert(resp.StatusCode, Equals, 200)
			c.Assert(len(body), Not(Equals), 0)
		}
	})
}
