$LOAD_PATH.unshift(File.expand_path("../..", __FILE__))

$: << '.'

require 'bundler'
Bundler.require

require 'sslackey'
require 'rspec'

require 'active_support/string_inquirer'
Dir[File.expand_path(File.join(File.dirname(__FILE__), "support/**/*.rb"))].each { |f| require f }

RSpec.configure do |config|
  config.mock_with :mocha
end

RSpec::Matchers.define :include_hash do |expected|
  match do |actual|
    actual.present? && actual.slice(*expected.keys) == expected
  end
end
