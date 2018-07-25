require 'openssl'
require 'json'
require 'base64'
require 'digest'
require 'rmagick'

R_COLOR_RANGE = [*0..255].freeze
G_COLOR_RANGE = [*0..255].freeze
B_COLOR_RANGE = [*0..255].freeze

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
    elsif req.get? && req.path == '/image'
      r = R_COLOR_RANGE.sample
      g = G_COLOR_RANGE.sample
      b = B_COLOR_RANGE.sample
      color = "##{"%02x"%r}#{"%02x"%g}#{"%02x"%b}"
      image = Magick::Image.new(100, 100) do |i|
        i.background_color = color
        i.format = 'png'
      end
      hash = Digest::SHA256.hexdigest(image.to_blob)
      [
        200,
        { 'Content-Type' => 'application/json' },
        [{ image: Base64.encode64(image.to_blob), hash: hash }.to_json]
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
