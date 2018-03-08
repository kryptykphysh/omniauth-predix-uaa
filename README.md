# Omniauth::Predix::UAA

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'omniauth-predix-uaa'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install omniauth-predix-uaa

## Usage

### In Rails

Add to your Gemfile, as above and run `bundle install`.

First ensure your UAA credentials are loaded in to the enviroment (perhaps using something like [dotenv](https://github.com/dotenv)). You will need to set your username (UAA_CLIENT), password (UAA_PASSWORD) and endpoint (UAA_URL).

To add this OmniAuth Strategy create an initializer, called `config/initializers/omniauth.rb` similar to the one below:

```ruby
require 'omniauth-predix-uaa'

Rails.application.config.middleware.use OmniAuth::Builder do
  provider :predixuaa,
           ENV['UAA_CLIENT'],
           ENV['UAA_PASSWORD'],
           {
             auth_server_url: ENV['UAA_URL'],
             token_server_url: ENV['UAA_URL']
           }
end
```

To use OmniAuth, you need only to redirect users to `/auth/predixuaa`. From there, OmniAuth will take over and take the user through the necessary steps to authenticate them with the chosen strategy.

I might then have a `SessionsController` with code that looks something like this:

```ruby
class SessionsController < ApplicationController
  def create
    @user = User.find_or_create_from_auth_hash(auth_hash)
    self.current_user = @user
    redirect_to '/'
  end

  protected

  def auth_hash
    request.env['omniauth.auth']
  end
end
```

The `omniauth.auth` key in the environment hash gives me my Authentication Hash which will contain information about the just authenticated user including a unique id, the strategy they just used for authentication, and personal details such as name and email address as available

To ensure the `SessionsController#create` action is called on authentication callback, you will also need to add something similar to the below to your `config/routes.rb` file:

`get '/auth/:provider/callback', to: 'sessions#create'`

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.build.ge.com/212630225/omniauth-predix-uaa. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.
