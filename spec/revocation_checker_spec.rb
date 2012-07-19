require 'spec_helper'
require 'openssl'
require 'tempfile'
require 'uri'
require 'lib/sslackey/revocation_checker'

describe RevocationChecker do

  def load_ocsp_enabled_cert
    ocsp_enabled_cert = File.read(File.expand_path "../fixtures/ocsp_enabled_cert.pem", __FILE__)
    OpenSSL::X509::Certificate.new(ocsp_enabled_cert)
  end

  def load_non_ocsp_cert
    crl_only_cert = File.read(File.expand_path "../fixtures/crl_only_cert.pem", __FILE__)
    OpenSSL::X509::Certificate.new(crl_only_cert)
  end

  def load_sample_ocsp_response
    File.open(File.expand_path "../fixtures/sample_ocsp_response.der", __FILE__)
  end

  def load_crl_without_cert_revoked
    File.read(File.expand_path "../fixtures/AkamaiSub3.crl", __FILE__)
  end

  def load_crl_with_cert_revoked
    File.read(File.expand_path "../fixtures/sample_certificate_revocation_list.crl", __FILE__)
  end

  describe ".setup" do
    it "caches trusted certificates correctly" do
      path = File.expand_path "../fixtures/cacert.pem", __FILE__
      RevocationChecker.setup(path)
      RevocationChecker.issuers.keys.size.should == 18
      RevocationChecker.issuers["FC:8A:50:BA:9E:B9:25:5A:7B:55:85:4F:95:00:63:8F:E9:58:6B:43"].serial.should == 121579451771502689459931452667480057963
      RevocationChecker.issuers_by_name.keys.size.should == 23
      RevocationChecker.issuers_by_name[301028566].serial.should == 185237570324729778462978133790525665700
      RevocationChecker.trusted_certs_file_path.should == path
    end
  end

  describe "#check_revocation_status" do
    it "uses the cached response when available" do
      cert = load_ocsp_enabled_cert
      cache = mock()
      cache.expects(:cached_response).with(cert).returns :successful
      cache.expects(:cache_response).never
      RevocationChecker.expects(:cache).returns cache
      AuthorityChecker.any_instance.expects(:validate).never
      checker = RevocationChecker.new
      checker.check_revocation_status(cert).should == :successful
    end

    it "retrieves the latest response and caches it when there's nothing in the cache" do
      cert = load_ocsp_enabled_cert
      cache = mock()
      cache.expects(:cached_response).with(cert).returns nil
      cache.expects(:cache_response).with(cert, :successful)
      RevocationChecker.expects(:cache).twice.returns cache
      AuthorityChecker.any_instance.expects(:validate).returns :successful
      checker = RevocationChecker.new
      checker.check_revocation_status(cert).should == :successful
    end
  end

  describe "#get_latest_revocation_status" do
    before do
      @revocation_checker = RevocationChecker.new
    end

    context "when authority key info extension exists" do
      it "retrieves the issuer certificate using the authority key info" do
        AuthorityChecker.any_instance.stubs(:validate)
        RevocationChecker.expects(:issuers).returns "stub issuer cert"
        cert = load_ocsp_enabled_cert
        @revocation_checker.get_latest_revocation_status(cert)
      end
    end

    context "when authority key info extension does not exist" do
      it "retrieves the issuer certificate using the issuer name" do
        RevocationChecker.stubs(:parse_authority_info_access)

        RevocationChecker.expects(:issuers_by_name).returns "stub issuer cert"
        cert = load_non_ocsp_cert
        @revocation_checker.get_latest_revocation_status(cert)
      end
    end

  end
end