class OrthrusTestSessions
  def initialize
    @keys = Hash.new { |h,k| h[k] = {} }
  end

  def add_key(user, key)
    @keys[user][key.public_identity] = key
  end

  def find_key(user, id)
    @keys[user][id]
  end

  def new_session(user, pub)
    @user = user
    @pub = pub
    [1, "secret"]
  end

  def find_session(id)
    ["secret", @pub]
  end

  def new_access_token(session_id)
    1
  end
end

