require 'orthrus/ssh'
require 'rack'

module Orthrus::SSH
  class RackApp
    def initialize(sessions)
      @sessions = sessions
    end

    attr_reader :sessions

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
      user = req.params['user']
      id = req.params["id"]

      unless pub = @sessions.find_key(user, id)
        return form("code=unknown")
      end

      session, nonce = @sessions.new_session(user, pub)

      form "code=check&session_id=#{session}&nonce=#{nonce}"
    end

    def verify(req)
      id = req.params["session_id"].to_i
      nonce, pub = @sessions.find_session(id)

      sig = req.params['sig']

      if pub.hexverify(sig, nonce)
        form "code=verified&access_token=1"
      else
        form "code=fail"
      end
    end
  end
end
