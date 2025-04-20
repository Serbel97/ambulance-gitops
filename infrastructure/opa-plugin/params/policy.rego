package wac.authz

import future.keywords.if
import input.attributes.request.http as http_request

default allow := false

# 1) Authenticated user?
is_valid_user := true if {
    http_request.headers["x-auth-request-email"]
}

user := {"valid": valid, "email": email, "name": name} if {
    valid := is_valid_user
    email := http_request.headers["x-auth-request-email"]
    name  := http_request.headers["x-auth-request-user"]
}

# 2) Which roles may access this path? (define a SET)
request_allowed_role["admin"]

request_allowed_role["monitoring"] if {
    glob.match("/monitoring*", [], http_request.path)
}

request_allowed_role["user"] if {
    not glob.match("/monitoring*", [], http_request.path)
    not glob.match("/http-echo*",    [], http_request.path)
}

# 3) Which roles does the user have? (define a SET)
user_role["user"] if {
    user.valid
}

user_role["admin"] if {
    [_, query] := split(http_request.path, "?")
    glob.match("am-i-admin=yes", [], query)
}

user_role["admin"] if {
    user.email == "xbelake@stuba.sk"
}

user_role["monitoring"] if {
    user.email == "erik.belak@gmail.com"
}

# 4) Action is allowed if there’s any overlap
action_allowed if {
    some role
    role in request_allowed_role
    role in user_role
}

# 5) Final allow decision
allow if {
    user.valid
    action_allowed
}

# 6) Response headers
headers["x-validated-by"]      := "opa-checkpoint"
headers["x-auth-request-roles"] := concat(", ", [ r | r in user_role ])

# 7) Output result
result := {"allowed": allow, "headers": headers}
