# ---------------------------------------------------------------------------- #
# Copyright 2010-2013, C12G Labs S.L                                           #
#                                                                              #
# Licensed under the Apache License, Version 2.0 (the "License"); you may      #
# not use this file except in compliance with the License. You may obtain      #
# a copy of the License at                                                     #
#                                                                              #
# http://www.apache.org/licenses/LICENSE-2.0                                   #
#                                                                              #
# Unless required by applicable law or agreed to in writing, software          #
# distributed under the License is distributed on an "AS IS" BASIS,            #
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.     #
# See the License for the specific language governing permissions and          #
# limitations under the License.                                               #
# ---------------------------------------------------------------------------- #

require 'rubygems'
require 'radius/dictionary'
require 'radius/packet'
require 'radius/auth'
require 'socket'

module OpenNebula; end

class OpenNebula::RadiusAuth
    def initialize(options)
#	puts options
        @options={
            :host => 'localhost',
	    :timeout => 5 ,
#            :port => 1812,
#            :user => nil,
#            :password => nil,
#            :secret => 'testing123',
#	    :auth => 'radius'
        }.merge(options)
#	puts "radius_auth"
#	puts options
        ops={}

        if @options[:user]
            ops[:auth] = {
                :username => @options[:user],
                :password => @options[:password]
            }
        end

#        ops[:radhost]=@options[:host] if @options[:host]
#	ops[:myip]=@options[:host] if @options[:myip]
#	ops[:timeout]=@ops
#        ops[:port]=@options[:port].to_i if @options[:port]
#	ops[:secret]=@options[:secret] if @options[:secret]
#        ops[:encryption]=@options[:encryption] if @options[:encryption]
#        puts "print"
#	puts options[:host]
#	puts options[:timeout]
	@radius=Radius::Auth.new(options[:host],"",options[:timeout])
#	puts "It connect radius server"
    end
=begin
    def find_user(name)
        begin
            result=@ldap.search(
                :base => @options[:base],
                :filter => "#{@options[:user_field]}=#{name}")

            if result && result.first
                [result.first.dn, result.first[@options[:user_group_field]]]
            else
                result=@ldap.search(:base => name)

                if result && result.first
                    [name, result.first[@options[:user_group_field]]]
                else
                    [nil, nil]
                end
            end
        rescue
            [nil, nil]
        end
    end
    def is_in_group?(user, group)
        result=@ldap.search(
                    :base   => group,
                    :filter => "(#{@options[:group_field]}=#{user.first})")

        if result && result.first
            true
        else
            false
        end
    end
=end
    def authenticate(user, pass,secret)
        radius=@radius.clone
#
#        auth={
#            :username => user,
#            :password => password,
#	    :secret   => secret
#        }

        if radius.check_passwd(user,pass,secret)
            true
        else
            false
        end
    end
end

