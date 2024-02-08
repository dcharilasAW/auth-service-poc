# demo-sso

Checked out from https://github.com/snezhinskiy/demo-sso  
See guide: https://medium.com/@d.snezhinskiy/building-sso-based-on-spring-authorization-server-part-1-of-3-68b3dda053fd

# Components

1. PostgresDB: setup with docker compose, login demosso-state/password
2. Authorization server (port 8080)
3. Resource server (port 8081)

# Roles & Authorities

| Role            | Authorities          |
|-----------------|----------------------|
| UNVERIFIED_USER | GAME_VIEW            |
| VERIFIED_USER   | GAME_VIEW, GAME_PLAY |

# Resources (Operations)

| Operation   | Required Authority | 
|-------------|--------------------|
| /games      | GAME_VIEW          | 
| /games/play | GAME_PLAY          | 

# Postman collection

[Auth Server PoC.postman_collection.json](Auth Server PoC.postman_collection.json)

# UI

Open http://localhost:8080/init.
Through this page you can perform registration or login. For login, the default OAuth2 Spring page is used.
You can verify the access token generation in `oauth2_authorization` table. The authentication is performed via authorization code grant type.

After successful login, you are navigated to the home page, which offers the following functionalities:
- **View games info**: This invokes the /games operation, which is available to all registered users.
- **Play games**: This invokes the /games/play operation, which is available only to verified users. If you have not verified your email, you should get an error.
- **Verify email**: This generates an OTP. In normal scenario this is sent to the user via email, for the purposes of this PoC it is simply logged. Once entered and verified, the user is assigned the VERIFIED_USER role, which unlocks access to play games.
- **Logout**: Resets the session and redirects to init page.