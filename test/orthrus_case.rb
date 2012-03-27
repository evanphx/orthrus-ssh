class OrthrusTestCase < MiniTest::Unit::TestCase
  DATA_PATH = File.expand_path "../data", __FILE__

  def setup
    @id_rsa = File.join DATA_PATH, "id_rsa"
    @rsa = Orthrus::SSH.load_private @id_rsa

    @rsa_pub = Orthrus::SSH.load_public File.join(DATA_PATH, "id_rsa.pub")
  end

  def added_to_agent(path)
    begin
      `chmod 0600 #{path}; ssh-add #{path} 2>&1`
      fail unless $?.exitstatus == 0

      yield
    ensure
      `ssh-add -d #{path} 2>&1`
    end
  end

end
