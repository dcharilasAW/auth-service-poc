# demo-sso

Checked out from https://github.com/snezhinskiy/demo-sso
See guide: https://medium.com/@d.snezhinskiy/building-sso-based-on-spring-authorization-server-part-1-of-3-68b3dda053fd

# Added features

1. Persist tokens (table oauth2_authorization)
2. Associate users with clients and Support same username in different client.

# Test data - Users

| Username   | Client       | Authorities                    |
|------------|--------------|--------------------------------|
| user       | demo-client  | read                           |
| admin      | demo-client  | read, write                    |
| admin      | admin-client | read, write, admin             |
| superadmin | admin-client | read, write, admin, superadmin |

