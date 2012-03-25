require 'orthrus/ssh'
require 'rack'

module Orthrus::SSH
  class RackApp
    def initialize(sessions)
      @keys = {}
      @sessions = sessions
    end

    attr_reader :keys

    def call(env)
      req = Rack::Request.new(env)

      case req.params['state']
      when 'find'
        find req
      when 'signed'
        verify req
      else
        [500, {}, ["unknown state"]]
      end
    end

    def form(body)
      [200,
       { "Content-Type" => "application/x-www-form-urlencoded" },
       [body]
      ]
    end

    def find(req)
      id = req.params["id"]
      unless pub = @keys[id]
        return form("code=unknown")
      end

      session, nonce = @sessions.new_session(pub)

      form "code=check&session_id=#{session}&nonce=#{nonce}"
    end

    def verify(req)
      id = req.params["session_id"].to_i
      nonce, pub = @sessions.find_session(id)

      sig = req.params['sig'].unpack("m").first

      if pub.verify(sig, nonce)
        form "code=verified&access_token=1"
      end
    end
  end
end
