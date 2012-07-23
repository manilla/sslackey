require 'redis'
require 'redis/namespace'
require 'active_support/all'

class RedisRevocationCache

  attr_accessor :redis, :expiration_seconds

  def initialize(redis_host, redis_port)
    @redis = Redis::Namespace.new(:revocation, :redis => Redis.new(:host => redis_host, :port => redis_port, :threadsafe => true))
    @expiration_seconds = 3600
  end

  def cached_response(certificate)
    response = redis.get(get_key(certificate))
    LOGGER.info("got a cached response: #{response}") if response && defined?(LOGGER)
    response.try(:to_sym)
  end

  def cache_response(certificate, response)
    key = get_key(certificate)
    LOGGER.info "caching revocation response for certificate: #{certificate.subject}" if defined?(LOGGER)
    redis.set(key, response)
    redis.expire(key, expiration_seconds)
  end

  def get_key(certificate)
    certificate.subject.hash
  end
end