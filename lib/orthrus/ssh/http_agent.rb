require 'orthrus/ssh'
require 'orthrus/ssh/agent'

require 'uri'

require 'net/http'

module Orthrus::SSH
  class HTTPAgent
    def initialize(url)
      @url = url
      @keys = []
      @access_token = nil
    end

    attr_reader :access_token

    def add_key(key)
      @keys << Orthrus::SSH.load_private(key)
    end

    def check(user, k)
      id = Rack::Utils.escape(k.public_identity)
      user = Rack::Utils.escape(user)

      url = @url + "?state=find&user=#{user}&id=#{id}"
      response = Net::HTTP.get_response url
      params = Rack::Utils.parse_query response.body

      return nil unless params["code"] == "check"

      [params['session_id'], params['nonce']]
    end

    def negotiate(k, sid, sig)
      sig = Rack::Utils.escape sig

      url = @url + "?state=signed&sig=#{sig}&session_id=#{sid}"

      response = Net::HTTP.get_response url
      params = Rack::Utils.parse_query response.body

      if params['code'] == "verified"
        return params['access_token']
      end

      return nil
    end

    def start(user)
      @keys.each do |k|
        sid, data = check(user, k)
        next unless sid

        sig = k.hexsign(data)

        token = negotiate(k, sid, sig)
        if token
          @access_token = token
          return
        end
      end

      if Agent.available?
        agent = Agent.connect
        agent.identities.each do |k|
          sid, data = check(user, k)
          next unless sid

          type, sig = agent.hexsign k, data

          token = negotiate(k, sid, sig)
          if token
            @access_token = token
            return
          end
        end
      end

      raise "Unable to find key to authenticate with"
    end
  end
end
