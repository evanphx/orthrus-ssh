require 'minitest/autorun'
require 'minitest/unit'

require 'orthrus/ssh/public_key_set'

class TestOrthrusSSHPublicKeySet < MiniTest::Unit::TestCase
  DATA_PATH = File.expand_path "../data", __FILE__

  def setup
    @auth_keys = File.join DATA_PATH, "authorized_keys"
    @id_dsa = File.join DATA_PATH, "id_dsa"
    @id_rsa = File.join DATA_PATH, "id_rsa"
  end

  def test_load_authorized_keys
    s = Orthrus::SSH::PublicKeySet.load_file @auth_keys
    assert_equal 2, s.num_keys
  end

  def test_find
    s = Orthrus::SSH::PublicKeySet.load_file @auth_keys
    k = Orthrus::SSH.load_private @id_rsa

    j = s.find(k.public_identity)

    assert_kind_of Orthrus::SSH::RSAPublicKey, j
  end

end
