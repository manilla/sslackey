require 'net/https'
require 'uri'
require 'logger'
require 'openssl'
require 'sslackey'


module OpenSSL
  module SSL
    class SSLSocket
      def post_connection_check(hostname)
        unless OpenSSL::SSL.verify_certificate_identity(peer_cert, hostname)
          raise SSLError, "hostname was not match with the server certificate"
        end

        checker = RevocationChecker.new()
        status = checker.check_revocation_status(peer_cert)
        raise SSLError, "Bad revocation status: #{status}" unless status == :successful

        return true
      end
    end
  end
end

RevocationChecker.setup File.join(File.dirname(__FILE__), 'cacert.pem')
RevocationChecker.cache = RedisRevocationCache.new("localhost", "6379")

#Test the connection
LOGGER = Logger.new(STDERR)

# tdameritrade.com is broken on ocsp parsing
# americanexpress.com : requires CRL check

url = URI.parse('https://www.google.com ')

http = Net::HTTP.new(url.host, url.port)
http.set_debug_output $stderr
http.use_ssl=true
store = OpenSSL::X509::Store.new
store.add_file File.join(File.dirname(__FILE__), 'cacert.pem')
http.cert_store = store
http.verify_mode = OpenSSL::SSL::VERIFY_PEER

http.start() do |http|
  request = Net::HTTP::Get.new url.request_uri
  response = http.request request # Net::HTTPResponse object
  puts response
end