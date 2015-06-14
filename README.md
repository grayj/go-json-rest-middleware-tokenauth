# go-json-rest-middleware-tokenauth
Token authentication middleware for go-json-rest

This package provides a [Go-Json-Rest](https://ant0ine.github.io/go-json-rest/) middleware useful for Token-based authentication. The middleware provides the following features:

* Extracting authentication tokens from an incoming Authorization header
* Injecting an appropriate WWW-Authenticate header for 401: Unauthorized
* Calling your supplied `Authenticator` and `Authorizer` functions and setting `request.Env["REMOTE_USER"].(string)`
* Secure generation of tokens, via `tokenauth.New() (string, error)`
* Secure comparison of tokens, via `tokenauth.Equal(string, string) bool`

Token storage and expiration are out of scope. Put them in your database with a created timestamp and User ID, or store them in Redis with a mapped User ID and an Expires time.

It's also advisable to rotate tokens periodically - it doesn't need to be every request, as this introduces a lot of logistical fun, but something on the order of days will help harden the app against replay and hijacking attacks.

Requests must be made over HTTPS, or your app will be about as secure as wet paper.

### When to use

Token auth appropriate for securing user sessions in a JavaScript application after initial password authentication.

The authentication routine is similar to both HTTP Basic Auth and the use of random IDs to track HTTP sessions. But we combine the "avoid accepting auth over cookies" of HTTP Basic Auth with the "use secure random IDs instead of user passwords for every request" found with the session IDs which most sites use after initial login.

**Token Auth vs. HTTP Basic Auth**

HTTP Basic Auth is deeply problematic for many use cases because the user password must be used for every request. It's great for handling the initial login if that's to be done over an API endpoint, and it's fine for many simple APIs in their early stages. But it should be avoided for user sessions, as this would require storing the user's password in a readable format.

Token Auth solves this problem by replacing the user's password with a disposable large random ID. We no longer ask the user to assert their account identity either - we restrict that to a lookup on the server.

For a recommended 256-bit random token, such IDs are very secure. If we further harden our service with a minimal effort to log and throttle failed auth attempts, it's unlikely that user sessions themselves will be a useful attack point.

**Token Auth vs. JSON Web Tokens**

There are a few use cases for JSON Web Tokens (JWT) which are worth considering. However, there are a few major weaknesses, the most critical of which is that you have no simple way to invalidate a token, because JWT trusts any signed token as an assertion that the provider is the linked user.

JWT is a clever solution to avoid server-side state...but server time is cheap and it's not that challenging to integrate a database. It's a solution to a problem we usually don't have, which unnecessarily complicates our security. If for some reason you have a non-static server and still need a stateless app, maybe consider JWT. But it's unusual to have both of those happen at the same time.

Token Auth relies on server-side storage of valid tokens, which means that token invalidation is as simple as issuing a DELETE query. And it is the antethesis of clever. You issue a long random ID, it maps to a known user. When a user provides the long random ID, you look it up to find out which user they are. Done.

**Token Auth vs. OAuth / OAuth 2**

OAuth is more full-featured than Token Auth, but also more complex on both the server and client sides. Token Auth should be thought of as "just enough complexity to secure the requests."

In general, prefer Token Auth to secure requests from your own app, and OAuth to secure public APIs which need to have more precise and consistent behavior. Requests in transit should be equally secure in either case (provided you use HTTPS!). The main difference is complexity and how the credentials behave over their lifecycle.

### Why don't we use HMAC signing?

If you want features like signed tokens, those can be implemented on top of the base Token Auth. However, this just creates a longer random number for an attacker to guess (or intercept). You can verify mathematically that you signed it...but you could already verify that you issued an unsigned token by looking up the answer, and 256-bit random IDs are already long enough to be [considered secure](https://gist.github.com/tqbf/be58d2d39690c3b366ad). For reference, they're enough to leave more than 10^67 addresses for every person on Earth. You won't have enough users to put a dent in that.

Similarly, we could sign requests, but it would be kind of pointless when we're transmitting the signing key along with the request. All it would prove is that the user's computer is capable of executing mathematical algorithms and getting a consistent answer. The alternative factoring here would be to sign the request and not transmit the token, which is a potentially valid choice. But then we'd need to have assertion of identity, and signing/unsigning complexity, and that's not the series of choices that Token Auth has made.

Token Auth is the "don't be clever" solution to user identity. Use HTTPS and 256-bit tokens. More security holes are caused by trying to be clever or by failing to cover the basics than by anything else.

### Installation

You can do the usual:

    go get github.com/grayj/go-user-passwords

Plus or minus "you should use godep" and possibly vendoring.
