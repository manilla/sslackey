require 'spec_helper'
require 'openssl'
require 'tempfile'
require 'uri'
require 'lib/sslackey/authority_checker'

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

describe AuthorityChecker do

  describe ".parse_authority_info_access" do

    context "with a multi line authority info string" do
      it "only finds the value that matches OCSP" do
        ocsp_string = "CA Issuers - URI:http://crt.usertrust.com/USERTrustLegacySecureServerCA.crt\nOCSP - URI:http://ocsp.usertrust.com\n"
        AuthorityChecker.parse_authority_info_access(ocsp_string).should == "http://ocsp.usertrust.com"

        ocsp_string = "OCSP - URI:http://ocsp.verisign.com\nCA Issuers - URI:http://SVRIntl-G3-aia.verisign.com/SVRIntlG3.cer\n"
        AuthorityChecker.parse_authority_info_access(ocsp_string).should == "http://ocsp.verisign.com"
      end
    end

    context "with a single authority info line" do
      it "finds the right value" do
        ocsp_string = "OCSP - URI:http ://ocsp.verisign.com"
        AuthorityChecker.parse_authority_info_access(ocsp_string).should == "http ://ocsp.verisign.com"
      end
    end
  end

  describe ".parse_crl_distribution_points" do
    context 'with a valid crl info string' do
      it "finds a matching crl url" do
        crl_string = "URI:http://crl.globalsign.net/AkamaiSub3.crl\n"
        AuthorityChecker.parse_crl_distribution_points(crl_string).should == "http://crl.globalsign.net/AkamaiSub3.crl"
      end
    end
  end

  describe "#validate" do
    before do
      @authority_checker = AuthorityChecker.new(nil)
    end
    context "when ocsp info present" do
      it "uses ocsp strategy to verify certificate" do
        AuthorityChecker.expects(:parse_authority_info_access).returns "ocsp.verisign.com"
        AuthorityChecker.stubs(:parse_crl_distribution_points)
        cert = load_ocsp_enabled_cert
        AuthorityChecker.any_instance.expects(:perform_ocsp_check).with(cert, "stub issuer cert", "ocsp.verisign.com").returns :successful
        @authority_checker.validate(cert, "stub issuer cert").should == :successful
      end
    end

    context "when only crl info present" do
      it "falls back to the crl strategy to verify the certificate" do
        AuthorityChecker.stubs(:parse_authority_info_access)
        AuthorityChecker.expects(:parse_crl_distribution_points).returns "crl.verisign.com"
        cert = load_non_ocsp_cert
        AuthorityChecker.any_instance.expects(:perform_crl_check).with(cert, "crl.verisign.com").returns :successful
        @authority_checker.validate(cert, "stub issuer certificate").should == :successful
      end
    end

    context "when neither crl or ocsp info is in the certificate" do
      it "blows up" do
        AuthorityChecker.stubs(:parse_crl_distribution_points)
        AuthorityChecker.any_instance.stubs(:perform_crl_check)

        cert = load_non_ocsp_cert
        expect { @authority_checker.validate(cert, "stub issuer cert") }.to raise_error(/Could not find valid oscp or crl extension/)
      end
    end
  end

  describe "#perform_crl_check" do
    it "returns a status of revoked when the certificate is on the crl" do
      crl_response = load_crl_with_cert_revoked
      AuthorityChecker.any_instance.expects(:fetch_crl_content).returns(crl_response)
      checker = AuthorityChecker.new(nil)

      cert = load_ocsp_enabled_cert
      checker.perform_crl_check(cert, nil).should == :revoked
    end

    it "returns a status of successful when the certificate is not on the crl" do
      crl_response = load_crl_without_cert_revoked
      AuthorityChecker.any_instance.expects(:fetch_crl_content).returns(crl_response)
      checker = AuthorityChecker.new(nil)

      cert = load_ocsp_enabled_cert
      checker.perform_crl_check(cert, "crl url").should == :successful
    end
  end

  describe "#perform_ocsp_check" do
    it "writes certificates to files and invokes open ssl verifier" do
      cert = mock()
      cert.expects(:path).returns "cert path"
      issuer_cert = mock()
      issuer_cert.expects(:path).returns "issuer path"
      response = mock()
      response.expects(:path).returns "response path"

      AuthorityChecker.any_instance.expects(:write_certificate_file).with(cert, "provider").returns cert
      AuthorityChecker.any_instance.expects(:write_certificate_file).with(issuer_cert, "issuer").returns issuer_cert
      AuthorityChecker.any_instance.expects(:create_response_file).returns(response).returns response
      AuthorityChecker.any_instance.expects(:read_ocsp_response).returns 'successful'

      AuthorityChecker.any_instance.expects(:generate_ocsp_response).with("issuer path", "cert path", "response path", "ocsp.verisign.com")

      checker = AuthorityChecker.new(nil)

      checker.perform_ocsp_check(cert, issuer_cert, "ocsp.verisign.com").should == :successful
    end
  end

  describe "#read_ocsp_response" do
    context "when a valid response is written to a file" do
      it "parses and reads a successful ocsp response correctly" do
        checker = AuthorityChecker.new(nil)
        checker.read_ocsp_response(load_sample_ocsp_response).should == 'successful'
      end
    end
  end


end

