require 'minitest/unit'

require 'orthrus/ssh/rack_app'
require 'orthrus/ssh/http_agent'

require 'sessions'

class TestOrthrusSSHHTTPAgent < MiniTest::Unit::TestCase
  DATA_PATH = File.expand_path "../data", __FILE__

  def setup
    @app = Orthrus::SSH::RackApp.new OrthrusTestSessions.new
    @server = Rack::Server.new :app => @app, :Port => 8787

    @old_stderr = $stderr
    $stderr = StringIO.new

    t = @thread = Thread.new do
      @server.start { |s| Thread.current[:server] = s }
    end

    sleep 1

    @id_rsa = File.join DATA_PATH, "id_rsa"
    @rsa = Orthrus::SSH.load_private @id_rsa

    @rsa_pub = Orthrus::SSH.load_public File.join(DATA_PATH, "id_rsa.pub")
    @app.sessions.add_key "evan", @rsa.public_identity, @rsa_pub
  end

  def teardown
    @thread.kill
    $stderr = @old_stderr
  end

  def test_access_token
    url = URI.parse "http://127.0.0.1:8787/"
    h = Orthrus::SSH::HTTPAgent.new url

    h.add_key @id_rsa

    h.start "evan"

    assert_equal "1", h.access_token
  end
end
