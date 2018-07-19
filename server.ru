require 'openssl'
require 'json'
require 'base64'
require 'digest'

class KeyManagement
  def initialize
    key = OpenSSL::PKey::EC.new('prime256v1')
    key.generate_key
    @key = key

    public_key = key.dup
    public_key.private_key = nil
    @public_key = public_key
  end

  def call(env)
    req = Rack::Request.new(env)

    if req.get? && req.path == '/public_key'
      [
        200,
        { 'Content-Type' => 'application/json' },
        [{ public_key: @public_key.to_pem }.to_json]
      ]
    elsif req.post? && req.path == '/signature'
      challenge = JSON.parse(env['rack.input'].read)['challenge']
      sign = @key.dsa_sign_asn1(Digest::SHA256.digest(challenge))
      encoded_sign = Base64.strict_encode64(sign)
      [
        200,
        { 'Content-Type' => 'application/json' },
        [{ signature: encoded_sign }.to_json]
      ]
    else
      [
        404,
        { 'Content-Type' => 'application/json' },
        [{ message: 'Not Found' }.to_json]
      ]
    end
  end
end

run KeyManagement.new
