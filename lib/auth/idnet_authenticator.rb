require 'auth/oauth2_authenticator'
require 'omniauth/strategies/idnet'
class Auth::IdnetAuthenticator < ::Auth::OAuth2Authenticator

  def after_authenticate(auth_token)
    result = Auth::Result.new

    oauth2_provider = auth_token[:provider]
    oauth2_uid = auth_token[:uid].to_s
    data = auth_token[:info]

    result.email = email = data['email']
    result.name = name = data['name']
    result.username = UserNameSuggester.find_available_username_based_on(data['username'])

    oauth2_user_info = Oauth2UserInfo.where(uid: oauth2_uid, provider: oauth2_provider).first

    if !oauth2_user_info && @opts[:trusted] && user = User.find_by_email(email)
      oauth2_user_info = Oauth2UserInfo.create(uid: oauth2_uid,
                                               provider: oauth2_provider,
                                               name: name,
                                               email: email,
                                               user: user)
    end

    result.user = oauth2_user_info.try(:user)
    result.email_valid = @opts[:trusted]

    result.extra_data = auth_token['extra']['raw_info']
    result
  end

  def register_middleware(omniauth)
    omniauth.provider :idnet, setup: lambda { |env|
      strategy = env["omniauth.strategy"]
      strategy.options.client_options = { site: SiteSetting.idnet_client_url }
      strategy.options.client_id = SiteSetting.idnet_client_id
      strategy.options.client_secret = SiteSetting.idnet_client_secret
    }
  end

end

