require 'minitest/unit'

require 'orthrus/ssh/agent'

class TestOrthrusSSHAgent < MiniTest::Unit::TestCase
  def setup
    @agent = nil
    skip unless Orthrus::SSH::Agent.available?
    @agent = Orthrus::SSH::Agent.connect
  end

  def teardown
    @agent.close if @agent
  end

  def test_identities
    assert_kind_of Array, @agent.identities
  end

  def test_sign
    id = @agent.identities.first

    data = "hello"

    type, sign = @agent.sign id, data

    assert id.verify(sign, data)
  end


end
