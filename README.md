# OPA Middleware Prototype

The purpose of this project was to prototype a Gorilla Mux middleware that would
query OPA and validate a policy against a given input from the HTTP client/user.
This input could be anything, but in this case, I kept it simple and just used
the value of a plain-text Authorization header.

## Try It
_I could set this up so it all worked with `docker-compose up`, but that will have to happen another time._

1. Start an OPA server: `docker run -it --rm -p 8181:8181 openpolicyagent/opa run --server --addr :8181`
2. Create the OPA policy.  See the call `PUT http://localhost:8181/v1/policies/simple1`
in `opa.http`.
3. Run the Go app: `go run main.go`
4. Make the call in `main.http` or run the tests in `main_tests.http`.

You will see that when the name after "Bearer" in the Authorization header is "john",
the call returns a 200, but when the name is changed to something else, the call returns
a 401.  This is specified not in the code, but in the policy in OPA.  The code simply
looks to see if the policy returns a true or false value for "allow".

## The Policy
This simple policy will evaluate to _true_ if the value given for "user" is "john".  Otherwise, it
will evaluate to _false_.  In the middleware code, we will split the phrase "Bearer " from the Authorization
header and supply the remainder as the input to the policy query, but the policy will reside on the OPA
server and the query will be evaluated there.  This keeps the authorization policy separate from the code.
```
package example.authz
import future.keywords.if

default allow := false

allow if {
    input.user = "john"
}
```


## HTTP vs Rego API
There are two functions that can be used by the middleware.  (It is not configurable, you will have
to change the code).

`evaluateOpaViaHttp` calls OPA via its HTTP API.  This is ideal
if there is already an instance of OPA running elsewhere in the architecture.
An improvement that needs to be done here is to parameterize the host and port for OPA, or the entire URL.
Even the query input could be abstracted somehow, so that it could be configurable between instances.

`evaluateOpaViaApi` does not call an OPA service, but instead validates the policy directly using the
Rego library to build and evaluate the query.  This has the obvious advantage of removing an HTTP round-trip
from the equation, but it introduces a new problem:  how to synchronize the policies with the middleware
or otherwise make them available.  This is a question that I did not explore.
