# Load all known issuer certs into memory. Key by cert name
require 'logger'
require 'openssl'
require 'tempfile'
require 'redis'
require 'redis/namespace'
require 'active_support/all'

class RevocationChecker
  @issuers = {}
  @issuers_by_name = {}
  @trusted_certs_file_path = nil
  @cache = nil

  class << self
    attr_accessor :issuers, :issuers_by_name, :trusted_certs_file_path, :cache
  end

  def self.setup(trusted_certs_file_path)
    RevocationChecker.issuers = {}
    RevocationChecker.issuers_by_name = {}

    RevocationChecker.trusted_certs_file_path = trusted_certs_file_path

    certs_file = File.read(RevocationChecker.trusted_certs_file_path)

    certs = certs_file.scan(/-----BEGIN CERTIFICATE-----[^-]*-----END CERTIFICATE-----/)

    certs.each do |cert|
      certificate = OpenSSL::X509::Certificate.new(cert)

      certificate.extensions.each do |extension|
        props = extension.to_h
        if props["oid"] == "subjectKeyIdentifier"
          issuer_key = props["value"]
          RevocationChecker.issuers[issuer_key] = certificate
        end
      end
      RevocationChecker.issuers_by_name[certificate.subject.hash] = certificate
    end
  end

  def check_revocation_status(certificate)
    if  cached_response = RevocationChecker.cache.cached_response(certificate)
      return cached_response
    end

    response = get_latest_revocation_status(certificate)

    RevocationChecker.cache.cache_response(certificate, response)

    response
  end

  def get_latest_revocation_status(certificate)
    issuer_certificate = nil
    certificate.extensions.each do |extension|
      props = extension.to_h
      if props["oid"] == "authorityKeyIdentifier"
        issuer_key = RevocationChecker.parse_authority_key_identifier(props["value"])
        issuer_certificate = RevocationChecker.issuers[issuer_key]
      end
    end

    unless issuer_certificate
      issuer_certificate = RevocationChecker.issuers_by_name[certificate.issuer.hash]
    end

    real_time_checker = AuthorityChecker.new(RevocationChecker.trusted_certs_file_path)
    response = real_time_checker.validate(certificate, issuer_certificate)

    response
  end

  def self.parse_authority_key_identifier(authority_key_identifier_string)
    authority_key_identifier_string.slice!(/keyid:/)
    authority_key_identifier_string.slice!(/\n/)
    authority_key_identifier_string
  end

end