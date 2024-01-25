# demo-sso

Checked out from https://github.com/snezhinskiy/demo-sso  
See guide: https://medium.com/@d.snezhinskiy/building-sso-based-on-spring-authorization-server-part-1-of-3-68b3dda053fd

# Test data - Users

| Username   | Client       | Authorities                    |
|------------|--------------|--------------------------------|
| user       | demo-client  | read                           |
| admin      | demo-client  | read, write                    |
| admin      | admin-client | read, write, admin             |
| superadmin | admin-client | read, write, admin, superadmin |

# Resources (Operations)

| Operation   | Required Authority | 
|-------------|--------------------|
| /public     | -                  | 
| /read       | read               | 
| /write      | write              | 
| /admin      | admin              | 
| /superadmin | superadmin         |

# Postman collection

[Auth Server PoC.postman_collection.json](Auth Server PoC.postman_collection.json)

0. Create a Global variable named `access_token`
1. Get access token (grant password) using the username, password & client of your choice (either _admin-client_ or _demo-client_)
2. Test roles API (either _read_, _write_, _admin_ or _superadmin_)

# Added features

1. Persist tokens (table oauth2_authorization)  -> get from auth-service
2. Associate users with clients and support same username in mutiple clients with different authorities.
3. User registration


# Next steps
- DB Lock (to support multiple instances) _-> get from auth-service_
- DB cleanup (expired tokens in oauth2_authorization) _-> get from auth-service_
- SSO
- Authorization of asynchronous services
- Add password encryption _-> get from auth-service_
- Add data to authorize system calls (e.g. scheduler)