# frozen_string_literal: true

require 'uaa'
require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class AccessToken
      DEFAULT_INFO = {
        'access_token' => '',
        'refresh_token' => '',
        'scope' => ''
      }.freeze

      attr_reader :auth_header
      attr_reader :info

      def initialize(info=DEFAULT_INFO, auth_header='')
        @info = info
        @auth_header = auth_header
      end

      def empty?
        @info == DEFAULT_INFO
      end
    end

    class Predixuaa
      include OmniAuth::Strategy

      args %i[client_id client_secret]

      option :async_calls, false
      option :auth_server_url, nil
      option :name, 'predixuaa'
      option :scope, nil
      option :skip_ssl_validation, false
      option :token_server_url, nil

      attr_accessor :access_token

      attr_reader :auth_server_url
      attr_reader :token_issuer
      attr_reader :token_server_url

      attr_writer :uaa_info

      def authorize_params
        params = options.authorize_params.merge(
          options.authorize_options.each_with_object({}) { |k, h| h[k.to_sym] = options[k] if options[k] }
        )
        if OmniAuth.config.test_mode
          @env ||= {}
          @env['rack.session'] ||= {}
        end
        params
      end

      def build_access_token(query_string)
        log :info, 'Fetching access token'
        token = client.authcode_grant(session.delete('redir_uri'), query_string)
        AccessToken.new(token.info, token.auth_header)
      rescue CF::UAA::InvalidToken => e
        log :error, "Invalid token: #{e.message}"
        AccessToken.new
      end

      def callback_phase
        if error = request.params['error_reason'] || request.params['error']
          fail!(
            error,
            CallbackError.new(
              request.params['error'],
              request.params['error_description'] || request.params['error_reason'],
              request.params['error_uri']
            )
          )
        end
        log :info, "In callback phase #{request.query_string}"
        self.access_token = build_access_token(request.query_string)
        self.access_token = refresh(access_token) if !access_token.empty? && expired?(access_token)
        log :info, "Got access token #{access_token.inspect}"
        super
      end

      def callback_url
        full_host + script_name + callback_path
      end

      def client
        ensure_auth_server_url
        ensure_token_server_url
        ensure_token_issuer
        log :info, "Client: #{options.client_id} auth_server: #{@auth_server_url} token_server: #{@token_server_url}"
        @token_issuer.logger = OmniAuth.logger
        @token_issuer
      end

      def expired?(access_token)
        access_token = access_token.auth_header if access_token.respond_to? :auth_header
        expiry = CF::UAA::TokenCoder.decode(access_token.split[1], nil, nil, false)[:expires_at]
        expiry.is_a?(Integer) && expiry <= Time.now.to_i
      end

      def prune!(hash)
        hash.delete_if do |_, value|
          prune!(value) if value.is_a?(Hash)
          value.nil? || (value.respond_to?(:empty?) && value.empty?)
        end
      end

      def raw_info
        @raw_info ||= uaa_info.whoami(access_token.auth_header)
        pp @raw_info
        @raw_info
      rescue CF::UAA::TargetError => e
        log :error, "#{e.message}: #{e.info}"
        {}
      end

      def refresh(access_token)
        log :info, 'Refreshing access token'
        client.refresh_token_grant(access_token.info[:refresh_token])
      end

      def request_phase
        authcode_uri = client.authcode_uri(callback_url, options.scope)
        log :info, "Redirect URI #{authcode_uri}"
        session['redir_uri'] = authcode_uri
        redirect authcode_uri
      end

      def token_params
        options.token_params.merge(
          options.token_options.each_with_object({}) { |k, h| h[k.to_sym] = options[k] if options[k] }
        )
      end

      def uaa_info
        @uaa_info ||= CF::UAA::Info.new(
          @token_server_url,
          skip_ssl_validation: options.skip_ssl_validation
        )
      end

      credentials do
        {
          'token' => access_token.info['access_token'],
          'refresh_token' => access_token.info['refresh_token'],
          'authorized_scopes' => access_token.info['scope']
        }
      end

      uid { raw_info['user_id'] || raw_info['email'] }

      info do
        prune!(
          name:         ['name'],
          email:        raw_info['email'],
          first_name:   ['given_name'],
          last_name:    raw_info['family_name']
        )
      end

      extra do
        hash = {}
        hash[:raw_info] = raw_info unless skip_info?
        prune! hash
      end

      class CallbackError < StandardError
        attr_accessor :error, :error_reason, :error_uri

        def initialize(error, error_reason = nil, error_uri = nil)
          self.error = error
          self.error_reason = error_reason
          self.error_uri = error_uri
        end

        def message
          [error, error_reason, error_uri].compact.join(' | ')
        end
      end

      private

      def ensure_auth_server_url
        return if @token_issuer
        return if @auth_server_url
        @auth_server_url ||= options.auth_server_url
        return if @auth_server_url.starts_with?('http')
        @auth_server_url = "https://#{@auth_server_url}"
      end

      def ensure_token_server_url
        return if @token_issuer
        return if @token_server_url
        @token_server_url = options.token_server_url || options.auth_server_url
        return if @token_server_url.starts_with?('http')
        @token_server_url = "https://#{@token_server_url}"
      end

      def ensure_token_issuer
        @token_issuer ||= CF::UAA::TokenIssuer.new(
          @auth_server_url,
          options.client_id,
          options.client_secret,
          skip_ssl_validation: options.skip_ssl_validation,
          token_target: @token_server_url
        )
      end
    end
  end
end
