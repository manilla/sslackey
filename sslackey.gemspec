# -*- encoding: utf-8 -*-
require File.expand_path('../lib/sslackey/version', __FILE__)

Gem::Specification.new do |gem|
  gem.authors       = ["Manilla", "Peter Krimmel"]
  gem.email         = ["engineering@manilla.com"]
  gem.description   = %q{Checks a certificate via ocsp or crl to see if it has been revoked}
  gem.summary       = %q{Ruby ssl certificate revocation checking}
  gem.homepage      = "http://chill.manilla.com"


  gem.add_runtime_dependency('resque') # locked to head of multithreaded c5 resque fork
  gem.add_runtime_dependency('activesupport') # locked at current Cypress/Redwood/Pine Rails version
  gem.add_runtime_dependency('redis', '2.2.2') # locked to prevent bumping binaries on upstream servers
  gem.add_runtime_dependency('redis-namespace')
  gem.add_runtime_dependency('i18n')
  gem.add_runtime_dependency('rake')
  gem.add_runtime_dependency('httparty') # locked at last working version

  gem.add_development_dependency('rspec')
  gem.add_development_dependency('mocha')
  gem.add_development_dependency('fuubar')
  gem.add_development_dependency('awesome_print')
  gem.add_development_dependency('ruby-debug19')
  gem.add_development_dependency('highline')



  gem.files         = `git ls-files`.split($\)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.name          = "sslackey"
  gem.require_paths = ["lib"]
  gem.version       = Sslackey::VERSION
end
