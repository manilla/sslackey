class AuthorityChecker
  REVOCATION_RESPONSES = [:successful, :unknown, :revoked]

  attr_accessor :trusted_certs_file_path

  def initialize(trusted_certs_path)
    @trusted_certs_file_path = trusted_certs_path

  end

  def validate(certificate, issuer_certificate)
    ocsp_url = nil
    crl_url = nil

    certificate.extensions.each do |extension|
      props = extension.to_h
      if props["oid"] == "authorityInfoAccess"
        ocsp_url = AuthorityChecker.parse_authority_info_access(props["value"])
        LOGGER.debug("Sslackey: got an ocsp url: #{ocsp_url}") if defined? LOGGER
      end

      if props["oid"] == "crlDistributionPoints"
        crl_url = AuthorityChecker.parse_crl_distribution_points(props["value"])
        LOGGER.debug("Sslackey: got an crl url: #{crl_url}") if defined? LOGGER
      end
    end
    if ocsp_url
      response = perform_ocsp_check(certificate, issuer_certificate, ocsp_url)
    elsif crl_url
      response = perform_crl_check(certificate, crl_url)
    else
      raise "Could not find valid oscp or crl extension to check against in certificate #{certificate.subject}"
    end

    raise "Unknown revocation response #{response}" unless AuthorityChecker::REVOCATION_RESPONSES.include?(response)

    response
  end

  def self.parse_authority_info_access(ocsp_string)
    ocsp_string.each_line do |line|
      if line.index(/OCSP/)
        urls = line.scan(/URI:.*/)
        url = urls[0]
        url.slice!(/URI:/)
        return url
      end
    end
    return nil
  end

  def self.parse_crl_distribution_points(crl_string)
    crl_string.each_line do |line|
      urls = line.scan(/URI:.*/)
      crl_url = urls[0]
      crl_url.slice!(/URI:/)
      return crl_url
    end
  end


  def perform_ocsp_check(certificate, issuer_certificate, ocsp_url)
    certificate_file = write_certificate_file(certificate, "provider")
    issuer_file = write_certificate_file(issuer_certificate, "issuer")
    output_file = create_response_file("ocsp_output")

    generate_ocsp_response(issuer_file.path, certificate_file.path, output_file.path, ocsp_url)

    read_ocsp_response(output_file).to_sym
  end

  def generate_ocsp_response(issuer_file_path, certificate_file_path, output_file_path, ocsp_url)
    `openssl ocsp -no_nonce -CAfile #{trusted_certs_file_path} -issuer #{issuer_file_path} -cert #{certificate_file_path} -respout #{output_file_path} -url #{ocsp_url}`
  end

  def read_ocsp_response(output_file)
    output_file.rewind
    response = OpenSSL::OCSP::Response.new(output_file.read)
    output_file.close
    response.status_string
  end

  def write_certificate_file(certificate, file_name)
    file = Tempfile.new(file_name)
    file.write(certificate)
    file.rewind
    file.close
    file
  end

  def create_response_file(file_name)
    Tempfile.new(file_name)
  end

  def perform_crl_check(certificate, crl_url)
    content = fetch_crl_content(crl_url)
    crl = OpenSSL::X509::CRL.new(content)

    revoked_matches = crl.revoked.select { |elem| elem.serial == certificate.serial }

    return :revoked unless revoked_matches.empty?

    :successful
  end

  def fetch_crl_content(crl_url)
    `curl -s '#{crl_url}'`
  end

end