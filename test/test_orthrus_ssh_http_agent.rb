require 'minitest/unit'

require 'orthrus/ssh/rack_app'
require 'orthrus/ssh/http_agent'

class TestOrthrusSSHHTTPAgent < MiniTest::Unit::TestCase
  DATA_PATH = File.expand_path "../data", __FILE__

  class Sessions
    def new_session(pub)
      @pub = pub
      [1, "secret"]
    end

    def find_session(id)
      ["secret", @pub]
    end

    def access_token
      "1"
    end
  end

  def setup
    @app = Orthrus::SSH::RackApp.new Sessions.new
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
    @app.keys[@rsa.public_identity] = @rsa_pub
  end

  def teardown
    @thread.kill
    $stderr = @old_stderr
  end

  def test_access_token
    url = URI.parse "http://127.0.0.1:8787/"
    h = Orthrus::SSH::HTTPAgent.new url

    h.add_key @id_rsa

    h.start

    assert_equal "1", h.access_token
  end
end
