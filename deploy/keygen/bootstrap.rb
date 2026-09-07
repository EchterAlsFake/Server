# Run after keygen:setup. Output credentials only into a protected mounted file.
account = Account.find(ENV.fetch('KEYGEN_ACCOUNT_ID'))
product = account.products.find_or_create_by!(name: 'Porn Fetch')
policy = product.policies.find_or_create_by!(name: 'Perpetual - 10 installations') do |p|
  p.account = account
  p.scheme = 'ED25519_SIGN'
  p.duration = nil
  p.strict = true
  p.floating = true
  p.max_machines = 10
  p.protected = true
  p.require_heartbeat = false
  p.require_check_in = false
  p.machine_uniqueness_strategy = 'UNIQUE_PER_LICENSE'
end
policy.update!(authentication_strategy: 'LICENSE')
path = '/app/credentials/product.json'
unless File.exist?(path)
  token = account.tokens.create!(bearer: product, name: 'Purchase fulfillment', expiry: nil)
  File.write(path, JSON.pretty_generate(
    account_id: account.id, product_id: product.id, policy_id: policy.id,
    public_key: account.ed25519_public_key, product_token: token.raw
  ), mode: 'w', perm: 0600)
end
puts 'Product and policy provisioned; credentials saved privately.'
