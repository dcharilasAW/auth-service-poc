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


# Added features

1. Persist tokens (table oauth2_authorization)
2. Associate users with clients and support same username in different client.
3. User registration


# Next steps
- DB Lock (to support multiple instances)
- DB cleanup (expired tokens in oauth2_authorization)
- SSO
- Authorization of asynchronous services
- Add password encryption