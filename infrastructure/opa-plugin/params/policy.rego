package wac.authz

import future.keywords.if
import future.keywords.contains
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

# 3) Which roles may access this path? (DEFINE A SET via contains) :contentReference[oaicite:0]{index=0}
#    - “admin” always allowed
request_allowed_role contains "admin"

#    - “monitoring” for /monitoring*
request_allowed_role contains "monitoring" if {
    glob.match("/monitoring*", [], http_request.path)
}

#    - “user” for everything else
request_allowed_role contains "user" if {
    not glob.match("/monitoring*", [], http_request.path)
    not glob.match("/http-echo*",    [], http_request.path)
}

# 4) Which roles does the user have? (DEFINE A SET)
user_role contains "user" if {
    is_valid_user
}

user_role contains "admin" if {
    [_, query] := split(http_request.path, "?")
    glob.match("am-i-admin=yes", [], query)
}

user_role contains "admin" if {
    user.email == "xbelake@stuba.sk"
}

user_role contains "monitoring" if {
    user.email == "erik.belak@gmail.com"
}

# 5) Action is allowed if there’s any intersection
action_allowed if {
    some role
    request_allowed_role[role]
    user_role[role]
}

# 6) Final allow decision
allow if {
    is_valid_user
    action_allowed
}

# 7) Response headers
headers["x-validated-by"]      := "opa-checkpoint"
headers["x-auth-request-roles"] := concat(", ", [ r | user_role[r] ])

# 8) Export final result
result := {"allowed": allow, "headers": headers}
