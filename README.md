# sslackey

Provides Online Certificate Status Protocol (OCSP) and certificate revocation list checking for ssl certificates.
Ruby ssl verifies the chain of trust for a certificate but does not by default check if the certificate has been revoked.


## Installation

Add this line to your application's Gemfile:

    gem 'sslackey'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install sslackey

## Requirements

* curl installation
* openssl installation
* Redis or implement your own caching mechanism

## Examples

```ruby
# Setup with your cache and trusted certs
RevocationChecker.setup File.join(File.dirname(__FILE__), 'cacert.pem')
RevocationChecker.cache = RedisRevocationCache.new("localhost", "6379")

# Start checking certs
checker = RevocationChecker.new()
status = checker.check_revocation_status(peer_cert)



## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Added some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
