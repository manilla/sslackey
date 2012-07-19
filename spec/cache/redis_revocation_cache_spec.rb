require 'spec_helper'
require 'redis'
require 'redis/namespace'
require 'active_support/all'
require 'lib/sslackey/cache/redis_revocation_cache'

describe RedisRevocationCache do

  describe "#initialize" do
    it "creates a new Redis with the correct host and port" do
      Redis::Namespace.expects(:new).returns "a redis namespace"
      Redis.expects(:new).with(:host => "redis.test.com", :port => 80, :threadsafe => true).returns "a redis"
      RedisRevocationCache.new("redis.test.com", 80)
    end
  end

  context "caching methods" do
    before do
      Redis::Namespace.stubs(:new).returns nil
      @redis = mock()
      @cache_service = RedisRevocationCache.new("some host", 90)
      @cache_service.redis = @redis
    end
    describe "#cached_response" do
      it "gets the symbolized response from redis" do
        @redis.expects(:get).with("12345").returns "successful"
        @cache_service.expects(:get_key).returns "12345"
        @cache_service.cached_response("some cert").should == :successful
      end

      it "returns nil response when no response cached" do
        @redis.expects(:get).with("12345").returns nil
        @cache_service.expects(:get_key).returns "12345"
        @cache_service.cached_response("some cert").should  be_nil
      end
    end

    describe "#cache_response" do
      it "sets the key in redis along with an expiration time" do
        cert = mock()
        cert.stubs(:subject)
        @redis.expects(:set).with("12345","successful").returns nil
        @redis.expects(:expire).with("12345", @cache_service.expiration_seconds)
        @cache_service.expects(:get_key).returns "12345"
        @cache_service.cache_response(cert,"successful")
      end
    end

    describe "#get_key" do
      it "uses the hash of the certificate subject name as the caching key" do
        cert = mock()
        cert.stubs(:subject)
        subject = mock()
        cert.expects(:subject).returns subject
        subject.expects(:hash).returns "12345"
        @cache_service.get_key(cert).should == "12345"
      end
    end

  end
end