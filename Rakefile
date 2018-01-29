require 'net/http'
require 'json'

@compliance_base_url = 'https://compliance.emea.chef.run/api'
@compliance_creds_file = '.compliance-creds'

task :setup_compliance_creds do
  puts 'Generating compliance token file...'
  puts 'Enter your userid:'
  userid = STDIN.gets.strip
  puts 'Enter your refresh token:'
  refresh_token = STDIN.gets.strip
  File.open(@compliance_creds_file, 'w') do |file|
    file.write("user_id: #{userid}\n")
    file.write("refresh_token: #{refresh_token}\n")
  end
end

task :add_compliance_node do
  unless File.exist?(@compliance_creds_file)
    puts "Compliance credentials file not found, run 'rake setup_compliance_creds' to (re)generate the file."
    next
  end

  user_id = File.read(@compliance_creds_file)[/.*user_id: ([^\n]*)/, 1]
  if user_id.nil?
    puts 'No user ID found in Compliance Credentials file, exiting.'
    next
  end

  refresh_token = File.read(@compliance_creds_file)[/.*refresh_token: ([^\n]*)/, 1]
  if refresh_token.nil?
    puts 'No refresh token found in Compliance Credentials file, exiting.'
    next
  end

  hostname = read_kitchen_file
  if hostname.nil?
    puts 'No hostname found in generated kitchen file'
    next
  end

  api_token = get_api_token(refresh_token)
  if api_token.nil?
    puts 'Compliance API token could not be obtained'
    next
  end

  upload_compliance_node(api_token, hostname, user_id)
end

def read_kitchen_file
  if File.exist?('./.kitchen/default-rhel-7.yml')
    hostname = File.read('./.kitchen/default-rhel-7.yml')[/.*hostname: ([^\n]*)/, 1]
    return hostname
  end
  nil
end

def get_api_token(refresh_token)
  url = URI.parse(@compliance_base_url + '/login')
  req = Net::HTTP::Post.new(url.to_s)
  req.body = "{\"token\": \"#{refresh_token}\"}"
  http = Net::HTTP.new(url.host, url.port)
  http.use_ssl = true
  res = http.request(req)
  if res.code == '200'
    body = JSON.parse(res.body)
    api_token = body['access_token']
    return api_token
  else
    puts 'Unexpected error getting access token'
  end
  nil
end

def upload_compliance_node(api_token, hostname, username)
  url = URI.parse(@compliance_base_url + "/owners/#{username}/nodes")
  req = Net::HTTP::Post.new(url.to_s)
  req.body = generate_body_json(hostname, username)
  req['Authorization'] = 'Bearer ' + api_token
  req['Content-Type'] = 'application/json'
  http = Net::HTTP.new(url.host, url.port)
  http.use_ssl = true
  res = http.request(req)
  puts 'Created new compliance node using UUID ' + res.body
end

def generate_body_json(hostname, username)
  [{
    hostname: hostname,
    environment: 'default',
    loginUser: 'ec2-user',
    loginMethod: 'ssh',
    loginKey: "#{username}/emea-sa-shared",
  }].to_json
end
