require 'minitest/autorun'
require 'minitest/unit'

require 'orthrus/ssh'

class TestOrthrusSSHDSA < MiniTest::Unit::TestCase
  DATA_PATH = File.expand_path "../data", __FILE__

  def setup
    @id_dsa = File.join DATA_PATH, "id_dsa"
    @id_dsa_pub = File.join DATA_PATH, "id_dsa.pub"
  end

  def pub_key
    Orthrus::SSH.load_public @id_dsa_pub
  end

  def priv_key
    Orthrus::SSH.load_private @id_dsa
  end

  def test_load_private
    s = Orthrus::SSH.load_private @id_dsa
    assert_kind_of Orthrus::SSH::PrivateKey, s
    assert s.dsa?, "key not dsa"
  end

  def test_load_public
    s = Orthrus::SSH.load_public @id_dsa_pub
    assert_kind_of Orthrus::SSH::PublicKey, s
    assert s.dsa?, "key not dsa"
  end

  def test_sign_and_verify
    data = "hello"

    assert pub_key.verify(priv_key.sign(data), data)
  end

  def test_public_identity
    s = Orthrus::SSH.load_private @id_dsa
    check = File.read(@id_dsa_pub).split(" ")[1]

    assert_equal check, s.public_identity
  end
end
