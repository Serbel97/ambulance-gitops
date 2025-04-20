package wac.authz

import future.keywords.if
import input.attributes.request.http as http_request

default allow := false

# 1) Authenticated user?
is_valid_user := true if {
    http_request.headers["x-auth-request-email"]
}

# 2) Build the user object
user := {"valid": valid, "email": email, "name": name} if {
    valid := is_valid_user
    email := http_request.headers["x-auth-request-email"]
    name  := http_request.headers["x-auth-request-user"]
}

# 3) Which roles may access this path? (as a SET via indexed rule‐heads)
request_allowed_role["admin"]

request_allowed_role["monitoring"] if {
    glob.match("/monitoring*", [], http_request.path)
}

request_allowed_role["user"] if {
    not glob.match("/monitoring*", [], http_request.path)
    not glob.match("/http-echo*",    [], http_request.path)
}

# 4) Which roles does the user have? (as a SET)
user_role["user"] if {
    is_valid_user
}

user_role["admin"] if {
    [_, query] := split(http_request.path, "?")
    glob.match("am-i-admin=yes", [], query)
}

user_role["admin"] if {
    user.email == "xbelak@stuba.sk"
}

user_role["monitoring"] if {
    user.email == "erik.belak@gmail.com"
}

# 5) Action is allowed if there's any overlap
action_allowed if {
    some role
    request_allowed_role[role]    # ← membership test without "in"
    user_role[role]               # ← ditto
}

# 6) Final allow decision
allow if {
    is_valid_user
    action_allowed
}

# 7) Response headers
headers["x-validated-by"]      := "opa-checkpoint"
headers["x-auth-request-roles"] := concat(", ", [ r | user_role[r] ])

# 8) Export result
result := {"allowed": allow, "headers": headers}
