# Explicit provisioning only; never run automatically during a website deployment.
# Credentials are written only to the protected mounted file.
account = Account.find(ENV.fetch('KEYGEN_ACCOUNT_ID'))
product = account.products.find_or_create_by!(name: 'Porn Fetch')
expected = {
  scheme: 'ED25519_SIGN', duration: 31_556_952,
  expiration_basis: 'FROM_FIRST_ACTIVATION', expiration_strategy: 'MAINTAIN_ACCESS',
  renewal_basis: 'FROM_NOW_IF_EXPIRED', max_machines: 10,
  authentication_strategy: 'LICENSE'
}
if ENV['KEYGEN_POLICY_ID'].to_s.empty?
  policy = product.policies.find_or_create_by!(name: 'Annual updates - 10 installations') do |p|
    p.account = account
    expected.each { |field, value| p.public_send("#{field}=", value) }
    p.strict = true
    p.floating = true
    p.protected = true
    p.require_heartbeat = false
    p.require_check_in = false
    p.machine_uniqueness_strategy = 'UNIQUE_PER_LICENSE'
  end
else
  policy = product.policies.find(ENV.fetch('KEYGEN_POLICY_ID'))
end
# Never rewrite an existing perpetual/beta policy or retroactively change licenses.
abort 'Policy does not match the annual commercial offer; existing policy was not modified.' unless expected.all? { |field, value| policy.public_send(field) == value }
path = '/app/credentials/product.json'
if File.exist?(path)
  saved = JSON.parse(File.read(path))
  abort 'Existing credential policy differs. Reconcile public client and server configuration explicitly; credentials were not overwritten.' unless saved.fetch('policy_id') == policy.id
else
  token = account.tokens.create!(bearer: product, name: 'Purchase fulfillment', expiry: nil)
  File.write(path, JSON.pretty_generate(
    account_id: account.id, product_id: product.id, policy_id: policy.id,
    public_key: account.ed25519_public_key, product_token: token.raw
  ), mode: 'w', perm: 0600)
end
puts 'Annual product policy verified; credentials saved privately. Match the shipped client policy before enabling purchases.'
