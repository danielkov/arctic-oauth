mod client;
mod error;
mod http;
mod oidc;
mod pkce;
mod providers;
mod request;
mod state;
mod tokens;

// Core
pub use client::OAuth2Client;
pub use error::Error;
pub use http::{HttpClient, HttpRequest, HttpResponse};
pub use tokens::OAuth2Tokens;

// Utilities
pub use oidc::decode_id_token;
pub use pkce::{CodeChallengeMethod, create_code_challenge, generate_code_verifier};
pub use state::generate_state;

// Default HTTP client (behind feature flag)
#[cfg(feature = "reqwest-client")]
pub use http::default_client;

// Providers (each behind its own feature flag)
#[cfg(feature = "amazon-cognito")]
pub use providers::amazon_cognito::{AmazonCognito, AmazonCognitoOptions};
#[cfg(feature = "anilist")]
pub use providers::anilist::{AniList, AniListOptions};
#[cfg(feature = "apple")]
pub use providers::apple::{Apple, AppleOptions};
#[cfg(feature = "atlassian")]
pub use providers::atlassian::{Atlassian, AtlassianOptions};
#[cfg(feature = "auth0")]
pub use providers::auth0::{Auth0, Auth0Options};
#[cfg(feature = "authentik")]
pub use providers::authentik::{Authentik, AuthentikOptions};
#[cfg(feature = "autodesk")]
pub use providers::autodesk::{Autodesk, AutodeskOptions};
#[cfg(feature = "battle-net")]
pub use providers::battle_net::{BattleNet, BattleNetOptions};
#[cfg(feature = "bitbucket")]
pub use providers::bitbucket::{Bitbucket, BitbucketOptions};
#[cfg(feature = "box-oauth")]
pub use providers::box_oauth::{BoxOAuth, BoxOAuthOptions};
#[cfg(feature = "bungie")]
pub use providers::bungie::{Bungie, BungieOptions};
#[cfg(feature = "coinbase")]
pub use providers::coinbase::{Coinbase, CoinbaseOptions};
#[cfg(feature = "discord")]
pub use providers::discord::{Discord, DiscordOptions};
#[cfg(feature = "donation-alerts")]
pub use providers::donation_alerts::{DonationAlerts, DonationAlertsOptions};
#[cfg(feature = "dribbble")]
pub use providers::dribbble::{Dribbble, DribbbleOptions};
#[cfg(feature = "dropbox")]
pub use providers::dropbox::{Dropbox, DropboxOptions};
#[cfg(feature = "epic-games")]
pub use providers::epic_games::{EpicGames, EpicGamesOptions};
#[cfg(feature = "etsy")]
pub use providers::etsy::{Etsy, EtsyOptions};
#[cfg(feature = "facebook")]
pub use providers::facebook::{Facebook, FacebookOptions};
#[cfg(feature = "figma")]
pub use providers::figma::{Figma, FigmaOptions};
#[cfg(feature = "forty-two")]
pub use providers::forty_two::{FortyTwo, FortyTwoOptions};
#[cfg(feature = "gitea")]
pub use providers::gitea::{Gitea, GiteaOptions};
#[cfg(feature = "github")]
pub use providers::github::{GitHub, GitHubOptions};
#[cfg(feature = "gitlab")]
pub use providers::gitlab::{GitLab, GitLabOptions};
#[cfg(feature = "google")]
pub use providers::google::{Google, GoogleOptions};
#[cfg(feature = "intuit")]
pub use providers::intuit::{Intuit, IntuitOptions};
#[cfg(feature = "kakao")]
pub use providers::kakao::{Kakao, KakaoOptions};
#[cfg(feature = "keycloak")]
pub use providers::keycloak::{KeyCloak, KeyCloakOptions};
#[cfg(feature = "kick")]
pub use providers::kick::{Kick, KickOptions};
#[cfg(feature = "lichess")]
pub use providers::lichess::{Lichess, LichessOptions};
#[cfg(feature = "line")]
pub use providers::line::{Line, LineOptions};
#[cfg(feature = "linear")]
pub use providers::linear::{Linear, LinearOptions};
#[cfg(feature = "linkedin")]
pub use providers::linkedin::{LinkedIn, LinkedInOptions};
#[cfg(feature = "mastodon")]
pub use providers::mastodon::{Mastodon, MastodonOptions};
#[cfg(feature = "mercado-libre")]
pub use providers::mercado_libre::{MercadoLibre, MercadoLibreOptions};
#[cfg(feature = "mercado-pago")]
pub use providers::mercado_pago::{MercadoPago, MercadoPagoOptions};
#[cfg(feature = "microsoft-entra-id")]
pub use providers::microsoft_entra_id::{MicrosoftEntraId, MicrosoftEntraIdOptions};
#[cfg(feature = "my-anime-list")]
pub use providers::my_anime_list::{MyAnimeList, MyAnimeListOptions};
#[cfg(feature = "naver")]
pub use providers::naver::{Naver, NaverOptions};
#[cfg(feature = "notion")]
pub use providers::notion::{Notion, NotionOptions};
#[cfg(feature = "okta")]
pub use providers::okta::{Okta, OktaOptions};
#[cfg(feature = "osu")]
pub use providers::osu::{Osu, OsuOptions};
#[cfg(feature = "patreon")]
pub use providers::patreon::{Patreon, PatreonOptions};
#[cfg(feature = "polar")]
pub use providers::polar::{Polar, PolarOptions};
#[cfg(feature = "reddit")]
pub use providers::reddit::{Reddit, RedditOptions};
#[cfg(feature = "roblox")]
pub use providers::roblox::{Roblox, RobloxOptions};
#[cfg(feature = "salesforce")]
pub use providers::salesforce::{Salesforce, SalesforceOptions};
#[cfg(feature = "shikimori")]
pub use providers::shikimori::{Shikimori, ShikimoriOptions};
#[cfg(feature = "slack")]
pub use providers::slack::{Slack, SlackOptions};
#[cfg(feature = "spotify")]
pub use providers::spotify::{Spotify, SpotifyOptions};
#[cfg(feature = "start-gg")]
pub use providers::start_gg::{StartGG, StartGGOptions};
#[cfg(feature = "strava")]
pub use providers::strava::{Strava, StravaOptions};
#[cfg(feature = "synology")]
pub use providers::synology::{Synology, SynologyOptions};
#[cfg(feature = "tiktok")]
pub use providers::tiktok::{TikTok, TikTokOptions};
#[cfg(feature = "tiltify")]
pub use providers::tiltify::{Tiltify, TiltifyOptions};
#[cfg(feature = "tumblr")]
pub use providers::tumblr::{Tumblr, TumblrOptions};
#[cfg(feature = "twitch")]
pub use providers::twitch::{Twitch, TwitchOptions};
#[cfg(feature = "twitter")]
pub use providers::twitter::{Twitter, TwitterOptions};
#[cfg(feature = "vk")]
pub use providers::vk::{VK, VKOptions};
#[cfg(feature = "withings")]
pub use providers::withings::{Withings, WithingsOptions};
#[cfg(feature = "workos")]
pub use providers::workos::{WorkOS, WorkOSOptions};
#[cfg(feature = "yahoo")]
pub use providers::yahoo::{Yahoo, YahooOptions};
#[cfg(feature = "yandex")]
pub use providers::yandex::{Yandex, YandexOptions};
#[cfg(feature = "zoom")]
pub use providers::zoom::{Zoom, ZoomOptions};
