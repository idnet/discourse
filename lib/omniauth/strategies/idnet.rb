require 'omniauth-oauth2'
class OmniAuth::Strategies::Idnet < OmniAuth::Strategies::OAuth2
  option :name, 'idnet'
  option :token_params, { response_type: 'token' }

  uid { raw_info['pid'] }

  info do
    {
      username: raw_info['nickname'],
      name: [raw_info['first_name'], raw_info['last_name']].join(' '),
      email: raw_info['email']
    }
  end

  extra do
    {
      raw_info: raw_info
    }
  end

  def raw_info
    JSON.parse(access_token.get('/api/v1/json/profile').body)
  end
end
