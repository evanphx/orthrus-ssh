require 'minitest/unit'
require 'minitest/autorun'

require 'orthrus/ssh'
require 'orthrus/ssh/rack_app'

require 'stringio'

require 'sessions'

class TestOrthrusSSHRackApp < MiniTest::Unit::TestCase
  DATA_PATH = File.expand_path "../data", __FILE__

  def setup
    @id_rsa = File.join DATA_PATH, "id_rsa"
    @rsa = Orthrus::SSH.load_private @id_rsa

    @id_rsa_pub = File.join DATA_PATH, "id_rsa.pub"
    @rsa_pub = Orthrus::SSH.load_public @id_rsa_pub

    @app = Orthrus::SSH::RackApp.new OrthrusTestSessions.new
  end

  def test_call_unable_to_find_identity
    id = @rsa.public_identity

    env = {
      "rack.input" => StringIO.new,
      "QUERY_STRING" => "state=find&user=evan&id=#{Rack::Utils.escape(id)}"
    }

    code, headers, body = @app.call(env)

    assert_equal "application/x-www-form-urlencoded",
                 headers["Content-Type"]

    params = Rack::Utils.parse_query body[0]
    assert_equal "unknown", params['code']
  end

  def test_call_requests_signature
    id = @rsa.public_identity
    @app.sessions.add_key "evan", @rsa_pub

    env = {
      "rack.input" => StringIO.new,
      "QUERY_STRING" => "state=find&user=evan&id=#{Rack::Utils.escape(id)}"
    }

    code, headers, body = @app.call(env)

    assert_equal "application/x-www-form-urlencoded",
                 headers["Content-Type"]

    params = Rack::Utils.parse_query body.first

    assert_equal "check", params['code']
    assert_equal "1", params["session_id"]
    refute params["nonce"].empty?
  end

  def test_call_verifies_signature
    id = @rsa.public_identity
    @app.sessions.add_key "evan", @rsa_pub

    env = {
      "rack.input" => StringIO.new,
      "QUERY_STRING" => "state=find&user=evan&id=#{Rack::Utils.escape(id)}"
    }

    code, headers, body = @app.call(env)

    params = Rack::Utils.parse_query(body.first)

    data = params['nonce']

    sig = Rack::Utils.escape @rsa.sign(data, true)

    env["QUERY_STRING"] = "state=signed&sig=#{sig}&session_id=1"

    code, headers, body = @app.call(env)

    params = Rack::Utils.parse_query body.first

    assert_equal "verified", params['code']
    assert_equal "1", params["access_token"]
  end
end
