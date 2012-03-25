require 'minitest/autorun'
require 'minitest/unit'

require 'orthrus/ssh'

class TestOrthrusSSHRSA < MiniTest::Unit::TestCase
  DATA_PATH = File.expand_path "../data", __FILE__

  def setup
    @id_rsa = File.join DATA_PATH, "id_rsa"
    @id_rsa_pub = File.join DATA_PATH, "id_rsa.pub"
  end

  def pub_key
    Orthrus::SSH.load_public @id_rsa_pub
  end

  def priv_key
    Orthrus::SSH.load_private @id_rsa
  end

  def test_load_private
    s = Orthrus::SSH.load_private @id_rsa
    assert_kind_of Orthrus::SSH::PrivateKey, s
    assert s.rsa?, "key not RSA"
  end

  def test_load_public
    s = Orthrus::SSH.load_public @id_rsa_pub
    assert_kind_of Orthrus::SSH::PublicKey, s
    assert s.rsa?, "key not RSA"
  end

  def test_sign_and_verify
    data = "hello"

    assert pub_key.verify(priv_key.sign(data), data)
  end

  def test_public_identity
    s = Orthrus::SSH.load_private @id_rsa
    check = File.read(@id_rsa_pub).split(" ")[1]

    assert_equal check, s.public_identity
  end
end
