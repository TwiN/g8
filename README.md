# g8

G8, pronounced Gate, is a simple Go library for protecting HTTP handlers with tokens.

Tired of constantly re-implementing a security layer for each of applications? Me too, that's why I made G8


## Installation

```
go get -u github.com/TwinProduction/g8
```


## Usage

Because the entire purpose of G8 is to NOT waste time configuring the layer of security, the primary emphasis is to 
keep it as simple as possible.


### Simple

Just want a simple layer of security without the need for advanced permissions? This configuration is what you're
looking for.

```go
gate := g8.NewGate(g8.NewAuthorizationService().WithToken("mytoken"))
router := http.NewServeMux()
router.Handle("/unprotected", yourHandler)
router.Handle("/protected", gate.Protect(yourHandler))
http.ListenAndServe(":8080", router)
```

The endpoint `/protected` is now only accessible if you pass the header `Authorization: Bearer mytoken`.

If you use `http.HandleFunc` instead of `http.Handle`, you may use `gate.ProtectFunc(yourHandler)` instead.


### Advanced permissions

If you have tokens with more permissions that others, g8's permission system will make managing authorization a breeze.

Rather than registering tokens, think of it as registering clients, the only difference being that clients may be 
configured with permissions while tokens cannot. 

```go
gate := g8.NewGate(g8.NewAuthorizationService().WithClient(g8.NewClient("mytoken").WithPermission("admin")))
router := http.NewServeMux()
router.Handle("/unprotected", yourHandler)
router.Handle("/protected-with-admin", gate.ProtectWithPermissions(yourHandler, []string{"admin"}))
http.ListenAndServe(":8080", router)
```

The endpoint `/protected-with-admin` is now only accessible if you pass the header `Authorization: Bearer mytoken`,
because the client with the token `mytoken` has the permission `admin`. Note that the following handler would also be
accessible with that token:
```
router.Handle("/protected", gate.Protect(yourHandler))
```

To clarify, both clients and tokens have access to handlers that aren't protected with extra permissions, and 
essentially, tokens are registered as clients with no extra permissions in the background.

Creating a token like so:
```go
gate := g8.NewGate(g8.NewAuthorizationService().WithToken("mytoken"))
```
is the equivalent of creating the following client:
```go
gate := g8.NewGate(g8.NewAuthorizationService().WithClient(g8.NewClient("mytoken")))
```


### With client provider

A client provider should be used when you have a lot of tokens and it wouldn't make sense to register all of them using
`AuthorizationService`'s `WithToken`/`WithTokens`/`WithClient`/`WithClients`.

```go
clientProvider := g8.NewClientProvider(func(token string) *Client {
    // We'll assume that the following function calls your database and returns a struct "User" that 
    // has the user's token as well as the permissions granted to said user
    user := database.GetUserByToken(token)
    if user != nil {
        return g8.NewClient(user.Token).WithPermissions(user.Permissions)
    }
    return nil
})
gate := g8.NewGate(g8.NewAuthorizationService().WithClientProvider(clientProvider))
```


## AuthorizationService

As the previous examples may have hinted, there are several ways to create clients. The one thing they have
in common is that they all go through AuthorizationService, which is in charge of both managing clients and determining
whether a request should be blocked or allowed through.

| Function | Description | 
|:--- |:--- |
| WithToken | Creates a single static client with no extra permissions
| WithTokens | Creates a slice of static clients with no extra permissions
| WithClient | Creates a single static client
| WithClients | Creates a slice of static clients
| WithClientProvider | Creates a client provider which will allow a fallback to a dynamic source (e.g. to a database) when a static client is not found 

Except for `WithClientProvider`, every functions listed above can be called more than once.
As a result, you may safely perform actions like this:
```go
authorizationService := g8.NewAuthorizationService().
    WithToken("123").
    WithToken("456").
    WithClient(g8.NewClient("789").WithPermission("admin"))
gate := g8.NewGate(authorizationService)
```

Be aware that g8.Client supports a list of permissions as well. You may call `WithPermission` several times, or call
`WithPermissions` with a slice of permissions instead.


### Permissions

Unlike client permissions, handler permissions are requirements.

A client with the permissions `create`, `read`, `update` and `delete` would have access to all of these handlers:
```go
gate := g8.NewGate(g8.NewAuthorizationService().WithClient(g8.NewClient("mytoken").WithPermissions([]string{"create", "read", "update", "delete"})))
router := http.NewServeMux()
router.Handle("/", gate.Protect(createHandler)) // equivalent of gate.ProtectWithPermissions(createHandler, []string{})
router.Handle("/create", gate.ProtectWithPermissions(createHandler, []string{"create"}))
router.Handle("/read", gate.ProtectWithPermissions(readHandler, []string{"read"}))
router.Handle("/update", gate.ProtectWithPermissions(updateHandler, []string{"update"}))
router.Handle("/delete", gate.ProtectWithPermissions(deleteHandler, []string{"delete"}))
router.Handle("/crud", gate.ProtectWithPermissions(crudHandler, []string{"create", "read", "update", "delete"}))
```
But it would not have access to the following handler, because while `mytoken` has the `read` permission, it does not 
have the `backup` permission:
```go
router.Handle("/backup", gate.ProtectWithPermissions(&testHandler{}, []string{"read", "backup"}))
```

