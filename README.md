# OV Auth
Creates JWT and SHA256 Tokens.

### Usage
#### JWT
- Use `TokenCreator` to encode and decode JWT's.
- `TokenGlobalFilter` Spring Component using `OncePerRequestFilter` for global request filters.
  - User whitelist for Swagger and H2 endpoints bypass.

#### Token
- `HmacToken` Create and validate `HmacSHA256` tokens.

### Requirements

