"""Default rule ids of the pinned Betterleaks image (1.9.0), from the configuration it embeds (`config/betterleaks.toml`
of that release).

Regenerate when the image in `engines.IMAGES` changes: the `id = "…"` lines of that file. A disabled rule the engine no
longer has is ignored by it (and dropped from the settings when they are read: secret_rules.get).
"""

DEFAULT_SECRET_RULES = tuple("""
    1password-secret-key 1password-service-account-token abuseipdb-api-key.1 adafruit-api-key adobe-client-id
    adobe-client-secret age-secret-key aikido-ci-token aikido-client-id aikido-client-secret airtable-api-key
    airtable-oauth-token airtable-personnal-access-token aiven-auth-token algolia-api-key algolia-application-id
    alibaba-access-key-id alibaba-secret-key alibaba-sts-access-key-id alibaba-sts-access-key-secret
    alibaba-sts-security-token amplitude-secret-key anthropic-admin-api-key anthropic-api-key apify-api-token
    apollo-api-key.1 artifactory-api-key artifactory-jfrog-url artifactory-reference-token asaas-api-token
    asana-client-id asana-client-secret assemblyai-api-key atlassian-api-token auth0-client-id.1 auth0-client-secret.1
    auth0-domain.1 authress-service-client-access-key aws-access-token aws-amazon-bedrock-api-key-long-lived
    aws-amazon-bedrock-api-key-short-lived aws-secret-access-key azure-ad-client-secret
    azure-app-configuration-connection-string azure-client-id azure-servicebus-connection-string
    azure-storage-account-key azure-storage-account-name azure-tenant-id beamer-api-token bitbucket-client-id
    bitbucket-client-secret bitbucket-data-center-token bitly-access-token bitrise-access-token bittrex-access-key
    bittrex-secret-key box-api-access-token brave-search-api-key browserstack-access-key.1 browserstack-username.1
    buildkite-service-token buildkite-user-access-token canadian-digital-service-notify-api-key canva-client-id
    canva-client-secret cartesia-api-key.1 cerebras-api-key checkout-secret-key circleci-personal-token
    circleci-project-token cisco-meraki-api-key civo-api-key clerk-secret-key clickhouse-cloud-api-secret-key
    clickhouse-cloud-key-id clickup-personal-api-token clojars-api-token cloudflare-api-key cloudflare-global-api-key
    cloudflare-origin-ca-key cloudinary-api-key cloudinary-api-secret cloudinary-cloud-name cloudsmith-api-key
    cockroachlabs-cloud-api-key codecov-access-token cohere-api-token coinbase-access-token configcat-sdk-key
    configcat-sdk-key-extended confluent-access-token confluent-secret-key contentful-delivery-api-token
    couchbase-capella-api-key coveralls-personal-api-token crates-io-api-key curl-auth-header curl-auth-user
    cursor-api-key databento-api-key databricks-api-token datadog-api-key datadog-application-key datagov-api-key
    datastax-astra-application-token deepgram-api-key deepseek-api-key defined-networking-api-token deno-account-token
    devcycle-client-sdk-key devcycle-mobile-sdk-key devcycle-server-sdk-key devin-personal-api-key devin-service-api-key
    devin-service-user-token digitalocean-access-token digitalocean-pat digitalocean-refresh-token discord-api-token
    discord-client-id discord-client-secret disqus-api-key docker-swarm-join-token docker-swarm-unlock-key
    dockerhub-organization-access-token dockerhub-personal-access-token doppler-api-token droneci-access-token
    dropbox-api-token dropbox-long-lived-api-token dropbox-short-lived-api-token duffel-api-token dynatrace-api-token
    easypost-api-token easypost-test-api-token ebay-client-id ebay-client-secret elastic-cloud-api-key
    elevenlabs-api-key endorlabs-api-key endorlabs-api-secret etsy-open-api-key exoscale-api-key exoscale-api-secret
    facebook-access-token facebook-page-access-token facebook-secret fal-api-key.1 fastly-api-token
    figma-personal-access-header-token figma-personal-access-token finicity-api-token finicity-client-secret
    finnhub-access-token flickr-access-token flutterwave-encryption-key flutterwave-public-key flutterwave-secret-key
    flyio-access-token frameio-api-token freemius-secret-key freshbooks-access-token fullstory-api-key gcp-api-key
    gcp-application-default-credentials gcp-gemini-api gcp-service-account generic-api-key generic-credential-uri
    generic-password generic-username gitea-access-token github-app-token github-fine-grained-pat github-oauth
    github-pat github-refresh-token gitlab-cicd-job-token gitlab-deploy-token gitlab-feature-flag-client-token
    gitlab-feed-token gitlab-incoming-mail-address-token gitlab-incoming-mail-token gitlab-kubernetes-agent-token
    gitlab-oauth-app-secret gitlab-pat gitlab-pat-routable gitlab-pat-routable-versioned gitlab-ptt gitlab-rrt
    gitlab-runner-authentication-token gitlab-runner-authentication-token-routable gitlab-scim-token
    gitlab-session-cookie gitter-access-token gocardless-api-token grafana-api-key grafana-cloud-api-token
    grafana-service-account-token greptile-api-key groq-api-key gumroad-access-token harness-api-key
    hashicorp-tf-api-token hashicorp-tf-password heroku-api-key heroku-api-key-v2 highnote-secret-live-key
    honeycomb-api-key hubspot-api-key huggingface-access-token huggingface-organization-api-token hunter-api-key.1
    ibm-cloud-user-api-key influxdb-api-token infomaniak-api-token infracost-api-token instantly-api-key.1
    intercom-api-key intra42-client-secret ionic-personal-access-token jumpcloud-api-key jwt jwt-base64 kagi-api-key
    kimi-api-key klaviyo-api-key kraken-access-token kubernetes-secret-yaml kucoin-access-token kucoin-secret-key
    langchain-langsmith-personal-access-token langchain-langsmith-service-key langfuse-public-key.1
    langfuse-secret-key.1 lark-app-id lark-app-secret launchdarkly-access-token lichess-personal-access-token
    lighton-paradigm-api-key linear-api-key linear-client-secret linkedin-client-id linkedin-client-secret
    llama-cloud-api-key.1 lob-api-key lob-pub-api-key looker-client-id looker-client-secret mailchimp-api-key
    mailersend-api-token mailgun-private-api-token mailgun-pub-key mailgun-signing-key mapbox-api-token
    mattermost-access-token maxmind-license-key mem0-api-key.1 mercury-production-api-token mergify-application-key
    messagebird-api-token messagebird-client-id microsoft-teams-webhook midtrans-production-server-client-key
    minimax-api-key miro-access-token miro-client-id miro-client-secret mistral-api-key monday-api-token.1
    mongodb-atlas-service-account-id mongodb-atlas-service-account-secret mongodb-connection-string
    mux-access-token-id.1 mux-access-token-secret.1 neon-api-key netlify-access-token new-relic-browser-api-token
    new-relic-insert-key new-relic-user-api-id new-relic-user-api-key ngrok-api-key.1 notion-api-token npm-access-token
    nuget-config-password nvidia-api-key nylas-api-key.1 nytimes-access-token octopus-deploy-api-key okta-access-token
    ollama-api-key onesignal-rich-authentication-token onfido-live-api-token-ca onfido-live-api-token-eu
    onfido-live-api-token-us openai-api-key openrouter-api-key openshift-user-token openweather-api-key
    opsgenie-api-key.1 ovh-application-key ovh-application-secret ovh-consumer-key paddle-live-api-key
    pagerduty-authorization-token.1 paypal-client-id.1 paypal-client-secret.1 perplexity-api-key
    persona-production-api-key pinecone-api-key.1 pinecone-api-key.2 pinterest-access-token pkcs12-file plaid-api-token
    plaid-client-id plaid-secret-key planetscale-api-token planetscale-id planetscale-oauth-token planetscale-password
    plivo-auth-id plivo-auth-token polar-oauth-access-token polar-organization-access-token polar-personal-access-token
    polymarket-address polymarket-api-key polymarket-api-secret polymarket-passphrase polymarket-private-key
    posthog-personal-api-key posthog-project-api-key postman-api-token postmark-api-token.1 prefect-api-token
    private-key privateai-api-token proof-full-access-api-key pulumi-api-token pypi-upload-token
    rainforest-pay-production-api-key ramp-client-id ramp-client-secret rapidapi-access-token razorpay-key-id.1
    razorpay-key-secret.1 readme-api-token redirect-pizza-api-token.1 render-api-key replicate-api-token
    resend-api-key.1 retell-api-key.1 rootly-api-key.1 rubygems-api-token runpod-api-key.1 salesforce-access-token.1
    salesforce-instance-url.1 samsara-api-token.1 scaleway-secret-key scalingo-api-token scalr-api-access-token.1
    segment-public-api-token.1 sendbird-access-id sendbird-access-token sendgrid-api-token sendinblue-api-token
    sentry-access-token sentry-org-token sentry-user-token settlemint-application-access-token
    settlemint-personal-access-token settlemint-service-access-token shippo-api-token shopify-access-token
    shopify-custom-access-token shopify-private-app-access-token shopify-shared-secret sidekiq-secret
    sidekiq-sensitive-url slack-app-token slack-bot-token slack-config-access-token slack-config-refresh-token
    slack-legacy-bot-token slack-legacy-token slack-legacy-workspace-token slack-session-cookie slack-session-token
    slack-user-token slack-webhook-url snowflake-account-host.1 snowflake-programmatic-access-token.1 snyk-api-token
    sonar-api-token sourcegraph-access-token square-access-token squarespace-access-token sslmate-api-key.1
    stability-ai-api-key stripe-access-token sumologic-access-id sumologic-access-token supabase-management-token
    supabase-project-api-key supabase-project-url tableau-personal-access-token-name.1 tableau-personal-access-token.1
    tableau-server-host.1 tailscale-api-key.1 telegram-bot-api-token telnyx-api-v2-key.1 temporal-cloud-api-key.1
    thunderstore-api-token.1 togetherai-api-key travisci-access-token twilio-api-key twitch-api-token
    twitter-access-secret twitter-access-token twitter-api-key twitter-api-secret twitter-bearer-token
    typeform-api-token unkey-root-key.1 upcloud-api-token upstage-api-key upstash-redis-rest-token.1
    upstash-redis-rest-url.1 val-town-api-token.1 vault-batch-token vault-service-token vercel-ai-gateway-key
    vercel-api-token vercel-app-access-token vercel-app-refresh-token vercel-integration-token
    vercel-personal-access-token virustotal-api-key.1 voyageai-api-key vultr-api-key.1 wakatime-api-key.1
    wakatime-api-key.2 weatherstack-api-key.1 weights-and-biases-api-key weights-and-biases-api-key-v1 wiz-client-id.1
    wiz-client-secret.1 woocommerce-consumer-secret.1 workato-developer-api-token.1 workos-production-api-key.1
    xai-api-key xendit-production-api-key.1 yandex-access-token yandex-api-key yandex-aws-access-token zai-api-key
    zendesk-secret-key zoho-client-id.1 zoho-client-secret.1 zoho-oauth-token.1 zoho-zapi-key.1 zuplo-consumer-api-key.1
""".split())

# Trivy rules that detect the same secret as a Betterleaks rule (same id, or a verified pair). Disabling the Betterleaks rule
# also disables its Trivy equivalent; rules without one keep running in Trivy.
TRIVY_EQUIVALENTS = {
    **{rule: rule for rule in (
        "adobe-client-id", "adobe-client-secret", "age-secret-key", "alibaba-access-key-id", "alibaba-secret-key",
        "asana-client-id", "asana-client-secret", "atlassian-api-token", "beamer-api-token", "bitbucket-client-id",
        "bitbucket-client-secret", "clojars-api-token", "contentful-delivery-api-token", "databricks-api-token",
        "discord-api-token", "discord-client-id", "discord-client-secret", "doppler-api-token",
        "dropbox-long-lived-api-token", "dropbox-short-lived-api-token", "duffel-api-token", "dynatrace-api-token",
        "easypost-api-token", "fastly-api-token", "finicity-api-token", "finicity-client-secret",
        "flutterwave-public-key", "frameio-api-token", "github-app-token", "github-fine-grained-pat", "github-oauth",
        "github-pat", "github-refresh-token", "gitlab-pat", "gocardless-api-token", "hashicorp-tf-api-token",
        "heroku-api-key", "linear-client-secret", "linkedin-client-id", "linkedin-client-secret", "lob-api-key",
        "lob-pub-api-key", "mailchimp-api-key", "mailgun-signing-key", "mapbox-api-token", "messagebird-api-token",
        "messagebird-client-id", "new-relic-browser-api-token", "new-relic-user-api-id", "new-relic-user-api-key",
        "npm-access-token", "planetscale-api-token", "planetscale-password", "postman-api-token", "private-key",
        "pulumi-api-token", "pypi-upload-token", "rubygems-api-token", "sendgrid-api-token", "sendinblue-api-token",
        "shippo-api-token", "twilio-api-key", "twitch-api-token", "typeform-api-token")},
    "aws-access-token": "aws-access-key-id",
    "huggingface-access-token": "hugging-face-access-token",
    "jwt": "jwt-token",
    "slack-webhook-url": "slack-web-hook",
    "stripe-access-token": "stripe-secret-token",
}

# The same secret under a Trivy rule that is broader than Betterleaks' one: Trivy's slack-access-token matches every
# `xox[baprs]-` token, Betterleaks names each kind. Equal for telling that both engines saw one secret (merge_secrets),
# never for turning rules off together: disabling Betterleaks' bot tokens mustn't silence Trivy's user tokens.
TRIVY_SAME_SECRET = {
    **TRIVY_EQUIVALENTS,
    **dict.fromkeys(("slack-bot-token", "slack-user-token", "slack-legacy-bot-token", "slack-legacy-workspace-token"),
                    "slack-access-token"),
}

# Built-in rules that start off: a credential URL is matched anywhere, so in practice it flags documentation examples
# and local connection strings more than secrets. An organization or a repository can turn it on (`enabled_rules`);
# disabled until then in every scan, and never counted as withheld.
OPT_IN_RULES = ("generic-credential-uri",)
# Formerly opt-in, now on by default behind the measured filter (secret_filter): an `enabled_rules` entry for one is
# accepted and has no effect.
FORMER_OPT_IN_RULES = ("generic-password",)


# Trivy 0.75.0's built-in allow rules (`builtinAllowRules`, pkg/fanal/secret/builtin-allow-rules.go of that tag): paths
# its secret scanner skips without a word (tests, examples, vendor, Markdown…). Pitangus turns them all off
# (`disable-allow-rules`) and its default skip patterns too (`skip-patterns: []`, node_modules, lockfiles, images…):
# only Pitangus' own allowlist applies. This list doesn't make the scan safe, the listing does (secret_coverage): a rule a
# later version adds and this list misses only leaves the files it skips unexamined, never taken as read.
TRIVY_BUILTIN_ALLOW_RULES = ("dist-info", "tests", "examples", "vendor", "usr-dirs", "locale-dir", "markdown", "node.js",
                             "golang", "python", "rubygems", "wordpress", "anaconda-log")
