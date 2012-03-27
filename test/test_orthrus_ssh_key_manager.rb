require 'minitest/unit'
require 'minitest/autorun'

require 'orthrus/ssh/key_manager'

require 'orthrus_case'

class TestOrthrusSSHKeyManager < OrthrusTestCase
  def setup
    super

    @kg = Orthrus::SSH::KeyManager.new
  end

  def test_add_key
    @kg.add_key @rsa

    assert_equal @rsa, @kg.keys.first
  end

  def test_load_key
    @kg.load_key @id_rsa
    assert_equal @rsa, @kg.keys.first
  end

  def test_agent_identities
    kg = @kg.agent_identities.first
    assert_kind_of Orthrus::SSH::Key, kg
  end

  def test_each_key
    @kg.add_key @rsa

    keys = []
    @kg.each_key { |x| keys << x }

    assert keys.include?(@rsa)
  end

  def test_each_keys_with_agent
    keys = []

    added_to_agent @id_rsa do
      @kg.each_key { |x| keys << x }
    end

    assert keys.include?(@rsa_pub)
  end

  def test_sign
    @kg.add_key @rsa

    data = "hello"
    sign = @kg.sign @rsa, data

    assert @rsa_pub.verify(sign, data)
  end

  def test_sign_with_agent
    added_to_agent @id_rsa do
      data = "hello"

      id = nil
      @kg.each_key do |k|
        if k == @rsa_pub
          id = k
          break
        end
      end

      assert id 

      sign = @kg.sign id, data
      assert @rsa_pub.verify(sign, data)
    end
  end
end
