
# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth/predix/uaa/version'

Gem::Specification.new do |spec|
  spec.name          = 'omniauth-predix-uaa'
  spec.version       = Omniauth::Predix::UAA::VERSION
  spec.authors       = ['Brian Wherry']
  spec.email         = ['brian.wherry@ge.com']

  spec.summary       = 'OmniAuth OAuth2 Strategy for Predix UAA.'
  spec.description   = File.read 'README.md'
  spec.homepage      = 'https://github.build.ge.com/212630225/omniauth-predix-uaa'
  spec.license       = 'MIT'

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the 'allowed_push_host'
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  if spec.respond_to?(:metadata)
    spec.metadata['allowed_push_host'] = 'https://devcloud.swcoe.ge.com/artifactory/gems'
  else
    raise 'RubyGems 2.0 or newer is required to protect against ' \
      'public gem pushes.'
  end

  spec.files = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_development_dependency 'bundler', '~> 1.16'
  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'rspec', '~> 3.0'
  spec.add_development_dependency 'rubocop', '~> 0.53'

  spec.add_runtime_dependency 'cf-uaa-lib', '~> 3.13'
  spec.add_runtime_dependency 'omniauth-oauth2' , '~> 1.5'
end