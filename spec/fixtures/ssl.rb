#useful utility to generating a certificate revocation list given a certificate you want to be revoked.
require 'openssl'
require 'active_support/all'


cert = OpenSSL::X509::Certificate.new(File.read("ocsp_enabled_cert.pem"))
serial = cert.serial

puts "cert serial: #{cert.serial}"
revoked = OpenSSL::X509::Revoked.new()
revoked.serial = serial
revoked.time = Time.now


puts "revoked: #{revoked.serial}"

crl = OpenSSL::X509::CRL.new

crl.add_revoked(revoked)
crl.last_update = 5.days.ago.to_time
crl.next_update= 5.days.from_now.to_time

puts crl.to_text

der = crl.to_der

output = File.open("sample_certificate_revocation_list.crl", "w")
output.write(der)
output.close