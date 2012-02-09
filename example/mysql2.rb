# 1/ create a database in mysql named "demo"
#
# 2/ oauth2-server register --db mysql2://root@localhost/demo
#   Running migration
#   Migration done
#   Application name:	demo
#   Application URL:	http://localhost:7654
#   Redirect URI:		http://localhost:7654/home
#   Scope (space separated names):		all
#   Registered demo
#   ID	d3ddcd403535012f2c731093e901604c
#   Secret	41bf0caa328b1b3986444961f90283dc1bbb5951c6d09c5f7ac84014bfa0eb60
#
#
# 3/ ruby examples/mysql2.rb
# 
# 4/ 

$:.unshift(File.dirname(__FILE__) + '/../lib')
require 'sinatra/base'
require "rack/oauth2/sinatra"
require 'sequel'
require 'mysql2'
require 'json'

class DemoServer < Sinatra::Base
  register Rack::OAuth2::Sinatra
  oauth[:database] = 'mysql2://root:@localhost/demo'

  get '/' do
    {
      :identity => oauth.identity,
      :access_token => oauth.access_token
    }.to_json
  end

  run! if app_file == $0
end
