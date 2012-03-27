require 'minitest/unit'
require 'minitest/autorun'

require 'orthrus/ssh/rack_app'
require 'orthrus/ssh/http_agent'

require 'stringio'

require 'sessions'
require 'orthrus_case'

class TestOrthrusSSHHTTPAgent < OrthrusTestCase
  def setup
    super

    @@app ||= Orthrus::SSH::RackApp.new OrthrusTestSessions.new
    @app = @@app
    @@server ||= begin
                   s = Rack::Server.new :app => @app, :Port => 8787
                   Thread.new { s.start }
                   s
                 end

    @old_stderr = $stderr
    $stderr = StringIO.new

    sleep 1

    @app.sessions.add_key "evan", @rsa_pub
  end

  def teardown
    # @thread.kill
    $stderr = @old_stderr
  end

  def test_access_token
    url = URI.parse "http://127.0.0.1:8787/"
    h = Orthrus::SSH::HTTPAgent.new url

    h.load_key @id_rsa

    h.start "evan"

    assert_equal "1", h.access_token
  end

  def test_access_token_from_agent
    skip unless Orthrus::SSH::Agent.available?

    added_to_agent @id_rsa do
      assert Orthrus::SSH::Agent.connect.identities.any? { |id|
               id.public_identity == @rsa_pub.public_identity
             }

      url = URI.parse "http://127.0.0.1:8787/"
      h = Orthrus::SSH::HTTPAgent.new url

      h.start "evan"

      assert_equal "1", h.access_token
    end
  end
end
