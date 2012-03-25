require 'orthrus/ssh'
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

    def start
      @keys.each do |k|
        id = Rack::Utils.escape(k.public_identity)

        url = @url + "?state=find&id=#{id}"
        response = Net::HTTP.get_response url
        params = Rack::Utils.parse_query response.body

        sid =  params['session_id']
        data = params['nonce']

        sig = Rack::Utils.escape [k.sign(data)].pack("m")

        url = @url + "?state=signed&sig=#{sig}&session_id=#{sid}"

        response = Net::HTTP.get_response url
        params = Rack::Utils.parse_query response.body

        if params['code'] == "verified"
          @access_token = params['access_token']
        end
      end
    end
  end
end
