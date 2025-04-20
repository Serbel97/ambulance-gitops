package wac.authz
import input.attributes.request.http as http_request

default allow = false

# define authenticated user
is_valid_user = true { http_request.headers["x-auth-request-email"] }

user = { "valid": valid, "email": email, "name": name} {
    valid := is_valid_user
    email := http_request.headers["x-auth-request-email"]
    name := http_request.headers["x-auth-request-user"]
}

# define required roles for paths
# admin role is allowed for any path
request_allowed_role["admin"] := true

# /monitoring path requires monitoring role
request_allowed_role["monitoring"] := true {
    glob.match("/monitoring*", [], http_request.path)
}

# user may access anything except /monitoring and /http-echo
# !!! DEMONSTRATION ONLY: this is not a good idea, because user
# !!! may access any path  that is not explicitely defined in request_allowed_role
# !!! in production use oposite logic: define white-listed paths
request_allowed_role["user"] := true {
    not glob.match("/monitoring*", [], http_request.path)
    not glob.match("/http-echo*", [], http_request.path)
}

# define roles for user

# any user with valid email is user
user_role["user"] {
    user.valid
}

# !!! DEMONSTRATION ONLY: backdoor for admin role
user_role[ "admin" ] {
    [_, query] := split(http_request.path, "?")
    glob.match("am-i-admin=yes", [], query)
}

# these are admin users
user_role[ "admin" ] {
    user.email == "xbelake@stuba.sk"
}

# these are users with access to monitoring actions
user_role[ "monitoring" ] {
    user.email == "erik.belak@gmail.com"
}

# action is allowed if there is some role that is in user roles
# and path roles simultanously
action_allowed {
    some role
    request_allowed_role[role]
    user_role[role]
}

# allow access if user is authenticated and action is allowed
allow {
    user.valid
    action_allowed
}

# set header to indicate that this policy was used to validate the request
headers["x-validated-by"] := "opa-checkpoint"

headers["x-auth-request-roles"] := concat(", ", [ role |
    some r
    user_role[r]
    role := r
])

# provide result to caller
result["allowed"] := allow
result["headers"] := headers
